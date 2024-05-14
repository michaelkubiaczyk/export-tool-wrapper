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
    "strings"
 
    "github.com/containerd/log"
    "github.com/cxpsemea/Cx1ClientGo"
    "github.com/cxpsemea/CxSASTClientGo"
    "github.com/google/uuid"
    "github.com/pkg/errors"
    "github.com/sirupsen/logrus"
    "github.com/sirupsen/logrus/hooks/writer"
    easy "github.com/t-tomalak/logrus-easy-formatter"
)
 
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
    ProjectName := flag.String("project", "", "Required: CxSAST project name")
 
    QueryMap := flag.String("querymapping", "bin/mappings-DEV.json", "Required: Path to query mapping file")
 
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
    if *SASTUrl == "" || *SASTUser == "" || *SASTPass == "" || *ProjectName == "" {
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
 
    logger.Infof("Retrieving listing of CxSAST projects matching %v", *ProjectName)
 
    var projects []CxSASTClientGo.Project
    pmap := make(map[int]string)
 
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
 
    re := regexp.MustCompile("(?i)" + *ProjectName)
 
    for _, p := range projects {
        if re.MatchString(p.Name) {
            logger.Infof("Project in scope: %v", p.String())
            pmap[int(p.ProjectID)] = *ProjectName
        }
    }
 
    logger.Infof("There are %d projects in scope matching %v", len(pmap), *ProjectName)
    if len(pmap) > 0 {
        migrationId := uuid.New()
        migrationRunner(migrationId.String(), *SASTUrl, *SASTUser, *SASTPass, *QueryMap, cx1client, &pmap, logger)
    }
}
 
func migrationRunner(migrationId, sasturl, sastuser, sastpass, querymapping string, cx1client *Cx1ClientGo.Cx1Client, projectMapping *map[int]string, logger *logrus.Logger) error {
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
    for pid, name := range *projectMapping {
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
            logger.Infof(" - Project ID %d -> %v", pid, (*projectMapping)[pid])
        }
    }
 
    bytes, err := json.Marshal(*projectMapping)
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
        archiveName, encryptionKeyFilename, _, warningMsgs, errorMsgs, err := execCxSastExporter(username, password, cxsast_url, projectBatches[batch], queryMappingFilePath, migrationId, projectMappingFile)
        if err != nil {
            return errors.Wrap(err, "Unable to export triage data from CxSAST")
        }
        if len(warningMsgs) > 0 {
            logger.Warnf("The following warnings happened during the export:\n" + strings.Join(warningMsgs, "\n"))
        }
        if len(errorMsgs) > 0 {
            logger.Errorf("The following errors happened during the export:\n" + strings.Join(errorMsgs, "\n"))
        }
        if err != nil {
            return errors.Wrap(err, "Unable to export triage data from CxSAST")
        }
        archivePath := filepath.FromSlash(migrationId + "/" + archiveName)
        encryptionKeyPath := filepath.FromSlash(migrationId + "/" + encryptionKeyFilename)
 
        result, err := doImport(encryptionKeyPath, archivePath, cx1client, logger)
        if err != nil {
            return errors.Wrapf(err, "Failed migrating batch %d of %d", batch+1, len(projectBatches))
        }
 
        logger.Infof("Migration data import batch %d of %d finished with status: %v", batch+1, len(projectBatches), result)
    }
 
    return nil
}
 
func execCxSastExporter(username, password, cxsast_url string, projectIds []int, queryMappingFilePath, migrationId, projectMappingFilePath string) (string, string, string, []string, []string, error) {
    var warnings = []string{}
    var errors = []string{}
    s, _ := json.Marshal(projectIds)
    commaSeparatedProjectIds := strings.Trim(string(s), "[]")
    exporterPath := "c:/work/code/cxsast-branch-migration/bin/cxsast_exporter.exe"
    externalFolderPath := "c:/work/code/cxsast-branch-migration/bin"
    // Create symlink so that the exporter can access the calculator from the current working directory
    os.Symlink(externalFolderPath, filepath.Join(migrationId, "external"))
    exporterCmd := exec.Command(exporterPath, "--user", username, "--pass", password, "--url", cxsast_url, "--project-id", commaSeparatedProjectIds, "--projects-active-since", "3650", "--export", "triage,projects", "--query-mapping", queryMappingFilePath, "--project-names", "project-map.json")
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
 
    result, err := cx1client.ImportPollingByIDWithTimeout(importID, 5, importTimeout)
    if err != nil {
        logger.Errorf("Failed during polling: %s", err)
        return "", fmt.Errorf("migration failed during execution")
    }
    return result, nil
}
