# pe32smvw
 PE32 data directories to sections map viewer console utility ver. 1.0.0.1

 Available options:
   -V(erbose) -	verbose output<br/>
   -A(dd):[SectionName=]Value(p) - add 'virtual' section with [SectionName] as name (tag) and Value bytes size (if p is present - Value is in pages)<br/>
   -F(ile add):[SectionName=]Filename[.ext] - add real (initialized) data section with [SectionName] as name (tag) and Filename as content<br/>

 Simple console utility application can be used to view map of PE32 sections. Also this utility is able to add a section descriptor for 'virtual' section or data section (content must be prepared in file).
 There is <a href="https://github.com/Victor-Soldatov/TestSMVW">test application</a> for experiments with this utility.

 Use makefile to build executable file. Adjust variables with valid pathes.
