package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/containerd/log"
	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/cxpsemea/CxSASTClientGo"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	easy "github.com/t-tomalak/logrus-easy-formatter"
)

var ScanMaxAge int = 3650
var statuslogger *logrus.Logger

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	myformatter := &easy.Formatter{}
	myformatter.TimestampFormat = "2006-01-02 15:04:05.000"
	myformatter.LogFormat = "[%lvl%][%time%] %msg%\n"
	logger.SetFormatter(myformatter)
	logger.SetOutput(os.Stdout)

	APIKey := flag.String("apikey", "", "CheckmarxOne API Key (if not using client id/secret)")
	ClientID := flag.String("client", "", "CheckmarxOne Client ID (if not using API Key)")
	ClientSecret := flag.String("secret", "", "CheckmarxOne Client Secret (if not using API Key)")
	Cx1URL := flag.String("cx1", "", "Optional: CheckmarxOne platform URL")
	IAMURL := flag.String("iam", "", "Optional: CheckmarxOne IAM URL")
	Tenant := flag.String("tenant", "", "Optional: CheckmarxOne tenant")
	LogLevel := flag.String("log", "INFO", "Log level: TRACE, DEBUG, INFO, WARNING, ERROR, FATAL")
	SASTProxy := flag.String("sastproxy", "", "Optional: Proxy to use when connecting to CxSAST Portal")
	Cx1Proxy := flag.String("cx1proxy", "", "Optional: Proxy to use when connecting to CheckmarxOne")

	SASTUrl := flag.String("sast", "", "Required: CxSAST platform URL")
	SASTUser := flag.String("user", "", "Required: CxSAST platform username")
	SASTPass := flag.String("pass", "", "Required: CxSAST platform password")
	ProjectName := flag.String("project", "", "Optional: CxSAST project name if parameter 'projects-file' is not used")
	ProjectsFile := flag.String("projects-file", "", "Optional: Text file containing one project name per line if parameter 'project' is not used")
	BatchSize := flag.Int("batchsize", 10, "Optional: Number of projects to export/import at a time")
	ScanMaxAge := flag.Int("maxage", 180, "Optional: Last scan must have run at least MaxAge days ago")
	FailVersion := flag.Bool("failversion", false, "Optional: Fail if the last scan was with CxSAST version 9.2 or earlier")
	LogFileName := flag.String("logfile", "log.txt", "Optional: Log file to output migration success/fail status")

	QueryMap := flag.String("querymapping", "bin/mappings-DEV.json", "Required: Path to query mapping file")
	ApplicationName := flag.String("application", "", "Optional: Name of the application into which the projects should be imported")

	flag.Parse()

	var err error

	switch strings.ToUpper(*LogLevel) {
	case "TRACE":
		logger.Info("Setting log level to TRACE")
		logger.SetLevel(logrus.TraceLevel)
	case "DEBUG":
		logger.Info("Setting log level to DEBUG")
		logger.SetLevel(logrus.DebugLevel)
	case "INFO":
		logger.Info("Setting log level to INFO")
		logger.SetLevel(logrus.InfoLevel)
	case "WARNING":
		logger.Info("Setting log level to WARNING")
		logger.SetLevel(logrus.WarnLevel)
	case "ERROR":
		logger.Info("Setting log level to ERROR")
		logger.SetLevel(logrus.ErrorLevel)
	case "FATAL":
		logger.Info("Setting log level to FATAL")
		logger.SetLevel(logrus.FatalLevel)
	default:
		logger.Info("Log level set to default: INFO")
	}

	var sastclient *CxSASTClientGo.SASTClient
	sasthttpClient := &http.Client{}

	// first SAST
	if *SASTUrl == "" || *SASTUser == "" || *SASTPass == "" || (*ProjectName == "" && *ProjectsFile == "") {
		logger.Fatalf("Invalid or missing SAST arguments supplied. Use -h for information.")
	}

	if *SASTProxy != "" {
		proxyURL, err := url.Parse(*SASTProxy)
		if err != nil {
			logger.Fatalf("Failed to parse specified SAST proxy address %v: %s", *SASTProxy, err)
		}
		transport := &http.Transport{}
		transport.Proxy = http.ProxyURL(proxyURL)
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

		sasthttpClient.Transport = transport
		logger.Infof("Running with SAST proxy: %v", *SASTProxy)
	}

	sastclient, err = CxSASTClientGo.NewTokenClient(sasthttpClient, *SASTUrl, *SASTUser, *SASTPass, logger)
	if err != nil {
		logger.Fatalf("Failed to create CxSAST client: %s", err)
	}

	var cx1client *Cx1ClientGo.Cx1Client
	cx1httpClient := &http.Client{}

	if *Cx1Proxy != "" {
		proxyURL, err := url.Parse(*Cx1Proxy)
		if err != nil {
			logger.Fatalf("Failed to parse specified CheckmarxOne proxy address %v: %s", *Cx1Proxy, err)
		}
		transport := &http.Transport{}
		transport.Proxy = http.ProxyURL(proxyURL)
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

		cx1httpClient.Transport = transport
		logger.Infof("Running with SAST proxy: %v", *Cx1Proxy)
	}

	if *Cx1URL == "" || *IAMURL == "" || *Tenant == "" || (*APIKey == "" && *ClientID == "" && *ClientSecret == "") || *QueryMap == "" {
		logger.Fatalf("Invalid or missing CheckmarxOne arguments supplied. Use -h for information.")
	}

	if *APIKey != "" {
		cx1client, err = Cx1ClientGo.NewAPIKeyClient(cx1httpClient, *Cx1URL, *IAMURL, *Tenant, *APIKey, logger)
	} else {
		cx1client, err = Cx1ClientGo.NewOAuthClient(cx1httpClient, *Cx1URL, *IAMURL, *Tenant, *ClientID, *ClientSecret, logger)
	}

	if err != nil {
		logger.Fatalf("Failed to create Cx1 client: %s", err)
	}

	logger.Infof("Created Cx1 client %s", cx1client.String())
	var projects []CxSASTClientGo.Project
	pmap := make(map[int]map[int]string)

	cache := "projects-cache.json"

	if bytes, err := os.ReadFile(cache); err == nil {
		logger.Infof("Loading projects data from cache file %v", cache)
		err = json.Unmarshal(bytes, &projects)
		if err != nil {
			logger.Fatalf("Failed to parse data from cache file %v: %s", cache, err)
		}
	} else {
		projects, err = sastclient.GetProjects()
		if err != nil {
			logger.Fatalf("Failed to get projects: %s", err)
		}

		bytes, err := json.Marshal(projects)
		if err != nil {
			logger.Fatalf("Failed to marshal project to json: %s", err)
		}

		if err = os.WriteFile(cache, bytes, 0666); err != nil {
			logger.Errorf("Failed to save cache to file %v: %s", cache, err)
		}
	}
	logger.Infof("Loaded %d projects", len(projects))

	var projectNames = []string{}
	if *ProjectsFile == "" {
		projectNames = append(projectNames, *ProjectName)
	} else {
		file, err := os.Open(*ProjectsFile)
		if err != nil {
			logger.Fatalf("Failed to open projects file %v: %s", *ProjectsFile, err)
		}

		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if len(scanner.Text()) > 1 {
				projectNames = append(projectNames, scanner.Text())
			}
		}
		if err := scanner.Err(); err != nil {
			logger.Fatalf("Failed while reading input file %s: %v", *ProjectsFile, err)
		}
	}

	logFile, err := os.OpenFile(*LogFileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		logger.Fatalf("Failed to open log file %v: %s", *LogFileName, err)
	}
	defer logFile.Close()
	statuslogger = logrus.New()
	statuslogger.SetLevel(logrus.InfoLevel)
	statuslogger.SetFormatter(myformatter)
	statuslogger.SetOutput(logFile)

	currentBatch := 0
	currentCount := 0
	pmap[currentBatch] = make(map[int]string)

	today := time.Now()

	logger.AddHook(&writer.Hook{ // Send logs to the statuslogger logfile in migration request folder
		Writer: logFile,
		LogLevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
			log.ErrorLevel,
			log.WarnLevel,
			log.InfoLevel,
			log.DebugLevel,
		},
	})

	branchCount := make(map[string][]int)

	for _, name := range projectNames {
		re := regexp.MustCompile("(?i)" + name)

		logger.Infof("Checking projects matching '%v'", name)
		branchCount[name] = make([]int, 0)

		for index, p := range projects {
			if re.MatchString(p.Name) {
				//logger.Infof(" - Project %v", p.String())
				lastscan, err := sastclient.GetLastScanByID(p.ProjectID)

				if err == nil {
					if lastscan.DateAndTime.FinishedOn.Before(today.AddDate(0, 0, -*ScanMaxAge)) {
						logger.Warningf(" x %v Last scan was over %d days ago: %v", p.String(), *ScanMaxAge, lastscan.DateAndTime.FinishedOn)
					} else if sastclient.CompareVersions(lastscan.ScanState.CxVersion, "9.3.0") < 0 && *FailVersion {
						logger.Warningf(" x %v Last scan version is too old - %v - should be at least 9.3, project will be excluded", p.String(), lastscan.ScanState.CxVersion)
					} else {
						logger.Infof(" + %v in scope", p.String())
						branchCount[name] = append(branchCount[name], index)
					}
				} else {
					logger.Warningf(" x %v Unable to retrieve last successful scan due to error %s, project will be excluded", p.String(), err)
				}
			}
		}
	}
	logger.Hooks = make(logrus.LevelHooks, 0)
	logger.Infof("There are %d projects in scope", len(pmap))

	sort.Slice(projectNames, func(i, j int) bool { return len(branchCount[projectNames[i]]) > len(branchCount[projectNames[j]]) })

	for _, name := range projectNames {
		logger.Infof("Group %d - %v with %d branches", currentBatch, name, len(branchCount[name]))

		if len(branchCount[name]) > 0 {

			for _, pindex := range branchCount[name] {
				pmap[currentBatch][int(projects[pindex].ProjectID)] = name

			}

			currentCount++
			if currentCount >= *BatchSize {
				currentCount = 0
				currentBatch++
				pmap[currentBatch] = make(map[int]string)
			}
		}
	}

	if len(pmap) > 0 {
		for group := range pmap {
			migrationId := uuid.New()
			migrationFolder := fmt.Sprintf("migration-%v", migrationId.String())
			statuslogger.Infof("Project Group %d of %d (sub-folder: %v):", group+1, len(pmap), migrationFolder)

			err = migrationRunner(migrationFolder, *SASTUrl, *SASTUser, *SASTPass, *QueryMap, cx1client, pmap[group], *ScanMaxAge, logger)
			if err != nil {
				logger.Errorf("Failed group %d migration: %s", group, err)
			}
		}
	}

	if *ApplicationName != "" {
		logger.AddHook(&writer.Hook{ // Send logs to the statuslogger logfile in migration request folder
			Writer: logFile,
			LogLevels: []log.Level{
				log.PanicLevel,
				log.FatalLevel,
				log.ErrorLevel,
				log.WarnLevel,
				log.InfoLevel,
				log.DebugLevel,
			},
		})

		AssignProjectsByName(cx1client, &projectNames, *ApplicationName, logger)
		AddProjectTags(cx1client, &projectNames, *ApplicationName, logger)

		logger.Hooks = make(logrus.LevelHooks, 0)
	}
}

func migrationRunner(migrationId, sasturl, sastuser, sastpass, querymapping string, cx1client *Cx1ClientGo.Cx1Client, projectMapping map[int]string, maxAge int, logger *logrus.Logger) error {
	/*
	   High level steps:
	   1. create projects and assign them to application
	   2. create project-level queries
	   3. create application-level queries
	   4. generate query mapping JSON
	   5. generate project mapping JSON
	   6. run sast-exporter to export only triage data, with the custom query mapping and project mapping
	   7. call CxONE APIs to import the triage data
	*/
	cxsast_url := sasturl
	username := sastuser
	password := sastpass
	productQueryMappingFilePath := querymapping

	err := os.Mkdir(migrationId, 0777)
	if err != nil {
		return errors.Wrap(err, "Failed to create folder for the migration request "+migrationId)
	}
	logFile, err := os.OpenFile(filepath.Join(migrationId, "migration-runner.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return errors.Wrap(err, "Failed to create log file for "+migrationId)
	}
	defer logFile.Close()
	logger.AddHook(&writer.Hook{ // Send logs to the logfile in migration request folder
		Writer: logFile,
		LogLevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
			log.ErrorLevel,
			log.WarnLevel,
			log.InfoLevel,
			log.DebugLevel,
		},
	})

	//projectIds := []string{}
	projectMappingByName := make(map[string][]int)

	// group Project IDs by target project name
	for pid, name := range projectMapping {
		projectMappingByName[name] = append(projectMappingByName[name], pid)
	}

	// create batches of projects to migrate based on the target name,
	// so that max one project per target name migrates per batch
	// eg: migrating
	//  [ Project1, Project2 ] -> "ProjectA" and also [ Project3, Project4 ] -> "ProjectB"
	// becomes:
	// Batch 1: Project1 -> ProjectA, Project3 -> ProjectB
	// Batch 2: Project2 -> ProjectA, Project4 -> ProjectB
	projectBatches := make([][]int, 0)
	done := false
	batchNumber := 0
	for !done {
		batch := make([]int, 0)
		for name := range projectMappingByName {
			if len(projectMappingByName[name]) > batchNumber {
				batch = append(batch, projectMappingByName[name][batchNumber])
				logger.Infof("Adding pid %d -> %v to batch %d", projectMappingByName[name][batchNumber], name, batchNumber)
			}
		}
		if len(batch) > 0 {
			projectBatches = append(projectBatches, batch)
		} else {
			done = true
		}
		batchNumber++
	}

	logger.Infof("Will migrate projects in the following batches")
	for batch := range projectBatches {
		logger.Infof("Batch #%d", batch+1)
		for _, pid := range projectBatches[batch] {
			logger.Infof(" - Project ID %d -> %v", pid, projectMapping[pid])
		}
	}

	bytes, err := json.Marshal(projectMapping)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal project mapping to json")
	}
	projectMappingFile := filepath.Join(migrationId, "project-map.json")
	if err := os.WriteFile(projectMappingFile, bytes, 0666); err != nil {
		return errors.Wrapf(err, "Failed to write project mapping to %v", projectMappingFile)
	}

	// generate query mapping file
	queryMappingFilePath := filepath.Join("..", productQueryMappingFilePath)
	// extract triage data from CxSAST

	for batch := range projectBatches {
		statuslogger.Infof("Batch %d of %d", batch+1, len(projectBatches))
		for _, pid := range projectBatches[batch] {
			statuslogger.Infof("Project ID #%d '%v'", pid, projectMapping[pid])
		}

		archiveName, encryptionKeyFilename, _, warningMsgs, errorMsgs, err := execCxSastExporter(username, password, cxsast_url, projectBatches[batch], queryMappingFilePath, migrationId, maxAge)
		if err != nil {
			retryCounter := 1
			retryDelay := 30
			for retryCounter < 3 {
				logger.Warningf("Export attempt %d/3 failed with error %v, waiting %d seconds to retry", retryCounter, err, retryDelay)

				time.Sleep(time.Duration(retryDelay) * time.Second)
				archiveName, encryptionKeyFilename, _, warningMsgs, errorMsgs, err = execCxSastExporter(username, password, cxsast_url, projectBatches[batch], queryMappingFilePath, migrationId, maxAge)
				if err == nil {
					break
				}
				retryCounter++
			}
		}

		if err != nil {
			logger.Errorf("Failed to export batch %d of %d", batch+1, len(projectBatches))
			statuslogger.Errorf("Failed to export (%s)", err)
		} else {
			statuslogger.Infof("Completed export")
			if len(warningMsgs) > 0 {
				logger.Warnf("The following warnings happened during the export:\n" + strings.Join(warningMsgs, "\n"))
			}
			if len(errorMsgs) > 0 {
				logger.Errorf("The following errors happened during the export:\n" + strings.Join(errorMsgs, "\n"))
			}
			archivePath := filepath.FromSlash(migrationId + "/" + archiveName)
			encryptionKeyPath := filepath.FromSlash(migrationId + "/" + encryptionKeyFilename)

			result, err := doImport(encryptionKeyPath, archivePath, cx1client, logger)
			if err != nil {
				retryCounter := 1
				retryDelay := 30
				for retryCounter < 3 {
					logger.Warningf("Import attempt %d/3 failed with error %v, waiting %d seconds to retry", retryCounter, err, retryDelay)

					time.Sleep(time.Duration(retryDelay) * time.Second)
					result, err = doImport(encryptionKeyPath, archivePath, cx1client, logger)
					if err == nil {
						break
					}
					retryCounter++
				}
			}

			if err != nil {
				logger.Errorf("Failed importing batch %d of %d: %s", batch+1, len(projectBatches), err)
				statuslogger.Errorf("Failed to import (%s)", err)
			} else {
				logger.Infof("Migration data import batch %d of %d finished with status: %v", batch+1, len(projectBatches), result)
				statuslogger.Infof("Completed import")
			}
		}
	}

	return nil
}

func execCxSastExporter(username, password, cxsast_url string, projectIds []int, queryMappingFilePath, migrationId string, maxAge int) (string, string, string, []string, []string, error) {
	var warnings = []string{}
	var errors = []string{}
	s, _ := json.Marshal(projectIds)
	commaSeparatedProjectIds := strings.Trim(string(s), "[]")
	exporterPath := "c:/work/code/cxsast-branch-migration/bin/cxsast_exporter.exe"
	externalFolderPath := "c:/work/code/cxsast-branch-migration/bin"
	// Create symlink so that the exporter can access the calculator from the current working directory
	os.Symlink(externalFolderPath, filepath.Join(migrationId, "external"))
	exporterCmd := exec.Command(exporterPath, "--user", username, "--pass", password, "--url", cxsast_url, "--project-id", commaSeparatedProjectIds, "--projects-active-since", fmt.Sprintf("%d", maxAge), "--export", "triage,projects", "--query-mapping", queryMappingFilePath, "--project-names", "project-map.json")
	exporterCmd.Dir = migrationId // set working directory to have a unique output folder
	exporterOut, _ := exporterCmd.StdoutPipe()
	err := exporterCmd.Start()
	if err != nil {
		switch e := err.(type) {
		case *exec.Error:
			fmt.Println("failed executing:", err)
			return "", "", "", warnings, errors, err
		case *exec.ExitError:
			fmt.Println("command exit rc =", e.ExitCode())
			return "", "", "", warnings, errors, err
		default:
			panic(err)
		}
	}
	scanner := bufio.NewScanner(exporterOut)
	scanner.Split(bufio.ScanLines)
	archiveName := ""
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)
		if strings.Contains(line, " WARN") {
			warnings = append(warnings, line)
		}
		if strings.Contains(line, " ERROR") {
			errors = append(errors, line)
		}
		var r *regexp.Regexp
		if strings.HasSuffix(line, ".zip") {
			r = regexp.MustCompile(`([A-Za-z]:)?[\\\/a-zA-Z_ \-0-9\[\](){}+=%$&]+(\/|\\)([a-zA-Z0-9_\-]+\.zip)`)
			matches := r.FindStringSubmatch(line)
			if len(matches) < 3 {
				return "", "", "", warnings, errors, fmt.Errorf("failed to parse archive filename from process output")
			}
			archiveName = matches[3]
		}
	}
	exitError := exporterCmd.Wait()
	if exitError != nil {
		return "", "", "", warnings, errors, fmt.Errorf("the SAST exporter did not complete succesfully, exit status code: %d", exitError.(*exec.ExitError).ExitCode())
	}
	if archiveName == "" {
		return "", "", "", warnings, errors, fmt.Errorf("failed to parse archive filename from process output")
	}
	logFilename := strings.Replace(archiveName, ".zip", ".log", 1)
	encryptionKeyFilename := strings.Replace(archiveName, ".zip", "-key.txt", 1)
	return archiveName, encryptionKeyFilename, logFilename, warnings, errors, nil
}

func doImport(encryptionKeyPath, archivePath string, cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger) (string, error) {
	// Call CxONE Migration API to import the triage data
	encryptionKeyBytes, err := os.ReadFile(encryptionKeyPath)
	encryptionKey := string(encryptionKeyBytes)
	if err != nil {
		logger.Errorf("Failed to read encryption key: %s", err)
		return "", fmt.Errorf("unable to read encryption key")
	}
	fileContents, err := os.ReadFile(archivePath)
	if err != nil {
		logger.Errorf("Failed to read zip file: %s", err)
		return "", fmt.Errorf("unable to read CxSAST archive data")
	}

	importID, err := cx1client.StartMigration(fileContents, []byte{}, encryptionKey) // no project-to-app mapping
	if err != nil {
		logger.Errorf("Failed to start migration: %s", err)
		return "", fmt.Errorf("failed to start migration")
	}

	// Set migration timeout for the polling
	importTimeout := 60 * 60 * 2 // 2 hours

	result, err := cx1client.ImportPollingByIDWithTimeout(importID, 30, importTimeout)
	if err != nil {
		logger.Errorf("Failed during polling: %s", err)
		return "", fmt.Errorf("migration failed during execution")
	}
	return result, nil
}

func AssignProjectsByName(cx1client *Cx1ClientGo.Cx1Client, projectNames *[]string, ApplicationName string, logger *logrus.Logger) {
	app, err := cx1client.GetApplicationByName(ApplicationName)
	if err != nil {
		logger.Errorf("failed to get target application %v: %s", ApplicationName, err)
		return
	}

	for _, name := range *projectNames {
		app.AddRule("project.name.in", name)

		if err = cx1client.UpdateApplication(&app); err != nil {
			logger.Errorf("Failed to add project %v to application %v: %s", name, app.String(), err)
		} else {
			logger.Infof("Added project %v to application %v", name, app.String())
		}
	}
}

func AddProjectTags(cx1client *Cx1ClientGo.Cx1Client, projectNames *[]string, ApplicationName string, logger *logrus.Logger) {
	appstr := fmt.Sprintf("App:%v", ApplicationName)
	for _, name := range *projectNames {
		proj, err := cx1client.GetProjectByName(name)
		if err != nil {
			logger.Errorf("Failed to get project %v from CheckmarxOne", name)
		}

		proj.Tags[appstr] = ""
		err = cx1client.UpdateProject(&proj)
		if err != nil {
			logger.Errorf("Failed to add tag to project %v", proj.String())
		}
	}
}
