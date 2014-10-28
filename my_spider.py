import socket

target = "192.168.11.175"
port = 80
links = {"/":0,"/twiki/bin/view/TWiki/IncludeTopicsAndWebPages":1}
bad_chars = ("#","?")



def get_data(link):
	if links[link] == 0:
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		s.connect((target,port))
		s.send("GET "+link+" HTTP/1.0\r\n\r\n")
		print "Getting",link
		page = s.recv(999999)
		s.close()
		links[link] = 1
		return page


def page_parser(html,parent):
	for line in html.split("href"):
		if len(line) > 0 and (line[0] ==  "=" or line[1] == "=") and '"' in line:
			link = line.split('\"')[1]
			if "://" in link or link[0] in bad_chars or len(link) == 0:
				continue
                        if not link[0] == "/":
                                link = parent + link
			if link in links.keys():
				continue
			else:
				links[link] = 0
			
while (0 in links.values()):
	keys = links.keys()
	for link in keys:
		print "page_parser",link
		html = get_data(link)
		if html:
			try:
				page_parser(html,link)
			except:
				print "error"
print links
