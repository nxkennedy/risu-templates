# Risu Templates
<table>
    <tr>
        <th>Version</th>
        <td>NA</td>
    </tr>
    <tr>
       <th>Author</th>
       <td>Nolan Kennedy (nxkennedy)</td>
    </tr>
    <tr>
        <th>Github</th>
        <td><a href="http://github.com/nxkennedy">http://github.com/nxkennedy</a></td>
    </tr>
</table>

### Description
Collection of modified files for Risu (https://github.com/hammackj/risu)

#### Templates Included:
* custom_failed_stig_check
Generate a DETAILED and ACCURATE pdf report of failed DISA STIG compliance checks from Nessus scans. Failed checks are organized by CAT level.

* custom_host_findings_csv
Generates a detailed csv report of vulnerabilities found which can be sorted for analysis

#### Other:
* Item.rb
Contains controller functions for templates

### Use Cases
* Reporting on failed DISA STIG checks by CAT level (something Nessus is terrible at doing)
* Building actionable vulnerability reports for System Engineers

### Requirements
* Ruby
* Risu Nessus Parser (https://github.com/hammackj/risu)
* MySQL DB

### Usage
* git clone https://github.com/nxkennedy/risu-templates.git
* Follow the Risu installation and setup instructions. These templates were run against a MySQL DB.
* Move these template files to ~/.risu/templates for risu to read them (you will have to create the .risu directory).
* Replace the default item.rb in the Risu gem directory. Example: /home/nxkennedy/.rvm/gems/ruby-2.4.0/gems/risu-1.8.3/lib/risu/models/item.rb
* A sample config file called 'risu.cfg' is included here. Use it as a reference for filling out your own.

### Output

(Sample Output Coming Soon!)
