This is for use with my fork of the sast-ast-export tool here: https://github.com/michaelkubiaczyk/sast-to-ast-export-mk

This fork allows renaming projects by passing in a mapping file containing data as below:

````
{
"ProjectID1": "TargetNameInCx1_1",
"ProjectID2": "TargetNameInCx1_2"
}
````

In some cases it may be useful to map multiple projects from CxSAST into one project in Cx1, for example:
- CxSAST "project_main" -> Cx1 "project", "main" branch
- CxSAST "project_FR123" -> Cx1 "project", "FR123" branch
- etc

````
{
"project_main ID#": "project",
"project_FR123 ID#": "project"
}
````

Unfortunately the result is that the import process will see the duplicate target names and will automatically rename the Cx1 projects to de-duplicate, resulting in the following:
- CxSAST "project_main" -> Cx1 "project"
- CxSAST "project_FR123" -> Cx1 "project_###" where the number is the CxSAST "project_FR123" project ID

This wrapper will take as input authentication credentials for CxSAST and Cx1 as well as a project name filter, and then it will do the following:
1. connect to CxSAST and retrieve all projects and filter for the provided string
2. generate the project-mapping file as shown above
3. run the export tool to generate the export zip for you, once for each project to be migrated
4. connect to CheckmarxOne and import the zip file for you

Note: there are two paths hardcoded, one for the cxsast_exporter.exe and one for the folder that includes the similarityID calculator which is bundled with the export tool. 
````
    exporterPath := "c:/work/code/cxsast-branch-migration/bin/cxsast_exporter.exe"
    externalFolderPath := "c:/work/code/cxsast-branch-migration/bin"
````
You'll want to update that to whatever suits your environment.
