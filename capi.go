/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main // import "github.com/mozilla/capi"

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/mozilla/capi/lib/ccadb"
	"github.com/mozilla/capi/lib/certificateUtils"
	"github.com/mozilla/capi/lib/expiration/certutil"
	"github.com/mozilla/capi/lib/model"
	"github.com/mozilla/capi/lib/service"
	"github.com/natefinch/lumberjack"
	log "github.com/sirupsen/logrus"
	"github.com/throttled/throttled"
	"github.com/throttled/throttled/store/memstore"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
)

func main() {
	InitLogging()
	store, err := memstore.New(65536)
	if err != nil {
		log.Fatal(err)
	}
	// 100 per minute, with a burst of 6.
	quota := throttled.RateQuota{MaxRate: throttled.PerMin(500), MaxBurst: 24}
	rateLimiter, err := throttled.NewGCRARateLimiter(store, quota)
	if err != nil {
		log.Fatal(err)
	}
	httpRateLimiter := throttled.HTTPRateLimiter{
		RateLimiter: rateLimiter,
		VaryBy:      &throttled.VaryBy{Path: true},
	}
	verifyLimiter := httpRateLimiter.RateLimit(http.HandlerFunc(verify))
	verifyCCADBLimiter := httpRateLimiter.RateLimit(http.HandlerFunc(verifyFromCCADB))
	http.Handle("/", verifyLimiter)
	http.Handle("/fromreport", verifyCCADBLimiter)
	port := Port()
	addr := BindingAddress()
	log.WithFields(log.Fields{"Binding Address": addr, "Port": port}).Info("Starting server")
	if err := http.ListenAndServe(addr+":"+string(port), nil); err != nil {
		log.Panicln(err)
	}
}

// The flow for verify is that, the moment that the value for desired response code and response body is known,
// that those variables be set and that the function return immediately. A deferred closure then reads these values
// an provides a single point of responding back to the client.
func verify(resp http.ResponseWriter, req *http.Request) {
	var response string
	var responseCode = http.StatusOK
	defer func() {
		if err := recover(); err != nil {
			responseCode = http.StatusBadGateway
			response = fmt.Sprintf("a fatal error has occured\n%s", err)
		}
		switch responseCode {
		case http.StatusBadGateway:
			log.Fatal(string(response))
		case http.StatusBadRequest:
			log.Error(responseCode)
		}
		resp.WriteHeader(responseCode)
		_, err := fmt.Fprintln(resp, string(response))
		if err != nil {
			// Oh my, perhaps the client hung up.
			log.WithField("response", string(response)).
				WithError(err).
				Fatal("failed to respond to the remote client")
			// This may or may not prove to be useful.
			// Leave it on debug because this can be incredibly noisy.
			dump, err := httputil.DumpRequest(req, false)
			switch err == nil {
			case true:
				log.WithField("wireRepresentation", dump).Debug()
			default:
				log.WithError(err).Fatal()
			}
		}
	}()
	dump, err := httputil.DumpRequest(req, false)
	if err != nil {
		responseCode = http.StatusBadGateway
		response = "a fatal internal error occurred, " + err.Error()
		return
	}
	log.WithField("Request", string(dump)).Info("Received request")
	log.Info(req.URL.RawQuery)
	query, err := url.ParseQuery(req.URL.RawQuery)
	log.Info(req.ParseForm())
	if err != nil {
		responseCode = http.StatusBadRequest
		response = "malformed query string, " + err.Error()
		return
	}
	s, ok := query["subject"]
	if !ok {
		responseCode = http.StatusBadRequest
		response = "'subject' query parameter is required"
		return
	}
	if len(s) == 0 {
		responseCode = http.StatusBadRequest
		response = "'subject' query parameter may not be empty"
		return
	}
	subject := s[0]
	if !strings.HasPrefix(subject, "https://") {
		subject = "https://" + subject
	}
	rawRoot, err := ioutil.ReadAll(req.Body)
	if err != nil {
		responseCode = http.StatusBadRequest
		response = "failed to read request body, " + err.Error()
		return
	}
	e, ok := query["expect"]
	interpretation := service.None
	log.Info(e)
	if ok {
		if len(e) == 0 {
			responseCode = http.StatusBadRequest
			response = "'expect' query parameter may not be empty"
			return
		}
		switch strings.ToLower(e[0]) {
		case "valid":
			interpretation = service.Valid
		case "expired":
			interpretation = service.Expired
		case "revoked":
			interpretation = service.Revoked
		}
	}
	log.Info("Expectation is " + strconv.Itoa(int(interpretation)))
	if err := req.Body.Close(); err != nil {
		responseCode = http.StatusBadGateway
		response = "failed to close the request body, " + err.Error()
		return
	}
	if len(rawRoot) == 0 {
		responseCode = http.StatusBadRequest
		response = "The PEM of the provided trust anchor cannot be empty."
	}
	rootPEM, err := certificateUtils.NormalizePEM(rawRoot)
	if err != nil {
		responseCode = http.StatusBadRequest
		response = "failed to format the provided PEM"
		return
	}
	log.Info(string(rootPEM))
	block, _ := pem.Decode(rootPEM)
	if block == nil {
		responseCode = http.StatusBadRequest
		response = "failed to decode the provided PEM"
		return
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		responseCode = http.StatusBadRequest
		response = "Bad root PEM, " + err.Error()
		return
	}
	// Now we can begin our actual work of tattling on the CA.
	result := model.TestWebsiteResult{SubjectURL: subject, Expectation: interpretation.String()}
	defer func() {
		switch r, err := json.MarshalIndent(result, "", "    "); err != nil {
		case true:
			responseCode = http.StatusBadGateway
			response = "a fatal error occurred when serializing the response, " + err.Error()
		case false:
			response = string(r)
		}
	}()
	// Reach out to the test website on a plain GET and extract the certificate chain from the request.
	chain, err := certificateUtils.GatherCertificateChain(string(subject))
	if err != nil {
		// Leave this as a 200 as the remote CA test website not responding
		// is a perfectly valid piece of information to report.
		result.Error = err.Error()
		result.Opinion.Bad = true
		return
	}
	// The test website may include a trust anchor. If it does, then swap it out with
	// the one our client wants to use, if not just tack our client's trust anchor onto the end.
	chain = certificateUtils.EmplaceRoot(chain, root)
	// And, finally, fill out chain verification information.
	result.Chain = service.VerifyChain(chain)
	service.InterpretResult(&result, interpretation)
	go SaveChainIfBad(result)
}

func verifyFromCCADB(resp http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			log.Error(err)
		}
		log.Info("dunnnn")
	}()
	report, err := ccadb.NewReport()
	if err != nil {
		resp.WriteHeader(500)
		resp.Write([]byte(err.Error()))
		return
	}
	ret := make(chan model.TestWebsiteResult, 30)
	work := make(chan ccadb.Record, len(report.Records))
	for _, record := range report.Records {
		work <- record
	}
	close(work)
	wg := sync.WaitGroup{}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for record := range work {
				root := record.Root()
				ret <- test(record.TestWebsiteValid(), root, service.Valid)
				ret <- test(record.TestWebsiteExpired(), root, service.Expired)
				ret <- test(record.TestWebsiteRevoked(), root, service.Revoked)
			}
		}()
	}
	go func() {
		wg.Wait()
		close(ret)
	}()
	resp.Write([]byte{'['})
	jsonResp := json.NewEncoder(resp)
	jsonResp.SetIndent("", "    ")
	// Because some OCSP responders are returning HTML
	//jsonResp.SetEscapeHTML(true)
	i := 0
	for answer := range ret {
		i++
		jsonResp.Encode(answer)
		if i < len(report.Records)*3 {
			resp.Write([]byte{','})
		}
		if flusher, ok := resp.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	resp.Write([]byte{']'})
}

func test(subject string, root *x509.Certificate, expectation service.Expectation) (result model.TestWebsiteResult) {
	result.SubjectURL = subject
	result.Expectation = expectation.String()
	if subject == "" {
		return
	}
	// Reach out to the test website on a plain GET and extract the certificate chain from the request.
	chain, err := certificateUtils.GatherCertificateChain(subject)
	if err != nil {
		// Leave this as a 200 as the remote CA test website not responding
		// is a perfectly valid piece of information to report.
		result.Error = err.Error()
		result.Opinion.Bad = true
		result.Opinion.Errors = append(result.Opinion.Errors, model.Concern{
			Raw:            err.Error(),
			Interpretation: "The subject test website failed to respond within 10 seconds.",
			Advise:         "Please check that " + subject + " is up and responding in a reasonable time.",
		})
		return
	}
	// The test website may include a trust anchor. If it does, then swap it out with
	// the one our client wants to use, if not just tack our client's trust anchor onto the end.
	chain = certificateUtils.EmplaceRoot(chain, root)
	// And, finally, fill out chain verification information.
	result.Chain = service.VerifyChain(chain)
	service.InterpretResult(&result, expectation)
	return
}

func SaveChainIfBad(result model.TestWebsiteResult) {
	if !result.Opinion.Bad {
		return
	}
	for _, err := range result.Opinion.Errors {
		var dirname string
		switch strings.Contains(err.Raw, certutil.ISSUER_UNKOWN) {
		case true:
			dirname = path.Join("dammit", result.Chain.Root.Fingerprint)
		case false:
			dirname = path.Join("yay", result.Chain.Root.Fingerprint)
		}
		writechain(dirname, result)
		f2, err := os.Create(path.Join(dirname, result.Expectation+"_result"))
		if err != nil {
			log.Panicln(err)
			return
		}
		defer f2.Close()
		enc := json.NewEncoder(f2)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			log.Panicln(err)
		}
	}
}

func writechain(dirname string, result model.TestWebsiteResult) {
	if err := os.MkdirAll(dirname, 0777); err != nil {
		log.Error(err)
		return
	}
	f, err := os.Create(path.Join(dirname, result.Expectation))
	if err != nil {
		log.Panicln(err)
		return
	}
	defer f.Close()
	for _, inter := range result.Chain.Intermediates {
		if err := pem.Encode(f, &pem.Block{"CERTIFICATE", nil, inter.Certificate.Raw}); err != nil {
			log.Panicln(err)
			return
		}
	}
	if err := pem.Encode(f, &pem.Block{"CERTIFICATE", nil, result.Chain.Leaf.Certificate.Raw}); err != nil {
		log.Panicln(err)
		return
	}
	rootf, err := os.Create(path.Join(dirname, result.Expectation+"_root"))
	if err != nil {
		log.Panicln(err)
		return
	}
	defer rootf.Close()
	if err := pem.Encode(rootf, &pem.Block{"CERTIFICATE", nil, result.Chain.Root.Certificate.Raw}); err != nil {
		log.Panicln(err)
		return
	}
}

func Home() string {
	switch home := os.Getenv("CAPI_HOME"); home {
	case "":
		return "."
	default:
		return home
	}
}

func Port() string {
	return fmt.Sprintf("%d", parseIntFromEnvOrDie("PORT", 8080))
}

func BindingAddress() string {
	switch addr := os.Getenv("ADDR"); addr {
	case "":
		return "0.0.0.0"
	default:
		_, _, err := net.ParseCIDR(addr)
		if err != nil {
			log.WithField("ADDR", addr).
				WithError(err).
				Error("failed to parse the provided ADDR to a valid CIDR")
			os.Exit(1)
		}
		return addr
	}
}

func LogFile() string {
	switch env := os.Getenv("LOG_DIR"); env {
	case "":
		return path.Join(Home(), "/logs/capi.log")
	default:
		return path.Join(env, "capi.log")
	}
}

func LogLevel() log.Level {
	switch lvl := os.Getenv("LOGLEVEL"); lvl {
	case "":
		return log.InfoLevel
	default:
		level, err := log.ParseLevel(lvl)
		if err != nil {
			// This is nipped straight from log.ParseLevel as
			// I don't see constants to refer to. If the version of logrus
			// included is ever bumped then this can migrate to being wrong.
			fmt.Printf("%s is not a valid logging level.\n", lvl)
			fmt.Println("Valid log levels are:")
			fmt.Println("> panic")
			fmt.Println("> fatal")
			fmt.Println("> error")
			fmt.Println("> warn OR warning")
			fmt.Println("> info")
			fmt.Println("> debug")
			fmt.Println("> trace")
			os.Exit(1)
		}
		return level
	}
}

func MaxLogSize() int {
	return parseIntFromEnvOrDie("MAXLOGSIZE", 12)
}

func MaxLogBackups() int {
	return parseIntFromEnvOrDie("MAXLOGBACKUPS", 12)
}

func MaxLogAge() int {
	return parseIntFromEnvOrDie("MAXLOGAGE", 31)
}

func Lumberjack() io.Writer {
	return &lumberjack.Logger{
		Filename:   LogFile(),
		MaxSize:    MaxLogSize(), // megabytes
		MaxBackups: MaxLogBackups(),
		MaxAge:     MaxLogAge(), //days
		Compress:   true,
	}
}

func LogWriter() io.Writer {
	switch isTTY := terminal.IsTerminal(int(os.Stdout.Fd())); isTTY {
	case true:
		// People sitting in front of their screen probably want
		// a copy of the logs to stdout.
		return io.MultiWriter(os.Stdout, Lumberjack())
	default:
		// Otherwise everything to just the file logger.
		return Lumberjack()
	}
}

func InitLogging() {
	log.SetLevel(LogLevel())
	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(LogWriter())
}

func parseIntFromEnvOrDie(key string, defaultVal int) int {
	switch val := os.Getenv(key); val {
	case "":
		return defaultVal
	default:
		i, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			fmt.Printf("%s (%s) could not be parsed to an integer", val, key)
			os.Exit(1)
		}
		return int(i)
	}
}
