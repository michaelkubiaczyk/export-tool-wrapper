This is for use with my fork of the sast-ast-export tool here: https://github.com/michaelkubiaczyk/sast-to-ast-export-mk

*Purpose*
The purpose of this tool is to automate migrations of large teams from CxSAST to CheckmarxOne. The specific use-case is for teams that have multiple projects in CxSAST, each representing a branch, for example: MyProject_main, MyProject_release1, MyProject_feature-2024q1
In this situation, the tool can be used to export the last-scan triage for "MyProject_main", "MyProject_release1" and "MyProject_feature-2024q1", and import those export-generated zip files into the same project "MyProject" in CheckmarxOne.

*Example usage*

go run . -sast "sastURL" -user "sastUser" -pass "sastPass" -projects-file <inputfile.txt> -cx1 "cx1URL" -iam "iamURL" -apikey <cx1 API Key> -tenant "cx1 tenant" -failversion -maxage 365 -application "name_of_cx1_app" -sast-field "sast custom field" -exporter-path "path/to/cxsast_exporter.exe"

The main input file -projects-file is a plain text file with the following format:
````
teamID1,project-name-substring1
teamID2,project-name-substring2
....
````

For the above scenario, if all of the "MyProject*" branch projects are located in a team with ID 1, the input file would contain only:
````
1,MyProject
````

This would select only the projects in team 1 with "MyProject" in the name to be in-scope for migration.

Additional parameters:
- failversion: ignore scans that were run on a CxSAST version prior to 9.3
- maxage 365: ignore scans run over 365 days prior
- sast-field "sast custom field": when migrating a project from CxSAST, update this custom field in CxSAST with the migration status afterwards
- exporter-path: path to the executable from https://github.com/michaelkubiaczyk/sast-to-ast-export-mk 
- groupsize: when there are multiple different projectnames provided, the tool will export/import those projects in groups with a maximum of this number of projects (eg: groupsize 10 = export/import 10 projects at a time)


*Process*
When you run the tool, it will repeatedly export data from CxSAST, generating a zip file for import into CheckmarxOne. If this fails, it will retry 3 times.
For each generated zip export, it will then import the zip into CheckmarxOne. If this fails, it will retry 3 times.
If the process failed for a set of projects, those projects will be written out to a file named "resume_<timestamp>.txt" - this is a list of "projectid,cx1_project_name" entries

Once the process is complete, you can check if the resume-file has any contents. These are the projects that failed to export or import. 

*Resume process*
This process can then be re-run using this resume-file as input, as an example this would be run like:

go run . -sast "sastURL" -user "sastUser" -pass "sastPass" -projects-file <inputfile.txt> -cx1 "cx1URL" -iam "iamURL" -apikey <cx1 API Key> -tenant "cx1 tenant" -application "name_of_cx1_app" -sast-field "sast custom field" -exporter-path "path/to/cxsast_exporter.exe" -groupsize 1 -resume "resume_<timestamp>.txt"

The primary changes in the command here are:
- removed -failversion and -maxage parameters: these are not relevant since those version/age checks were done previously in the first-run. 
- added -resume parameter pointing to the file generated in the first-run
- added -groupsize 1 parameter: the default is to export 10 projects at a time, but if one project fails to export then the whole batch of 10 fails. By resuming with a smaller group-size like 1, the process will repeat but export/import one project at a time, so any projects that still fail are likely unable to be migrated.

