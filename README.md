# pi_tool
Webpage monitor for raspberry pi

This is a web based monitoring tool for the Raspberry Pi servers written in jQuery, Javascript and PHP. It uses SNMP and SSH protocols to communicate
with your pi to query data such as Hardware Stats, Software Stats and Network Stats from it. It uses the libraries: Phpseclib 2.0+ for SSH connectivity and
php-snmp for SNMP v2c. An AJAX request is sent from the script1.js file to the ssh.php file every 'x' seconds to SSH or SNMP request
data from it. 

This tool makes uses of string parsing in some cases for SSH to display data from the terminal to the webpage.
This tool has been tested only on "2016-12-13-pixel-x86-jessie.iso" running on virtualbox since I don't have a real raspberry pi.

Please note that you need to have SNMP configured to work with remote IP's and SSH setup correctly for this tool to work.

The login page first runs an SSH test to the pi and then an SNMP test to the pi by running a simple ls and system time command respectively.
If both return as true then session is set in the browser for the entered IP, Username, Password and Community name. This is then used to
run SSH and SNMP commands every 'x' seconds.

Here's a link to the image gallery:
http://imgur.com/a/0mdZd

This tool shows the service status of services like "mysql", "ssh", "ntp", "snmpd", "apache2", "bluetooth", "networking", "cron". These are stored in an array on line 247 in ssh.php . Please edit the services according your needs.

///This is a very basic project and no implementations to make it secure have been done. All that is coming in the future//

Run this tool on your webserver and make sure you can ssh your pi from that network.
