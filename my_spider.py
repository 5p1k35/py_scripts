#This script was created to cause plenty of network traffic and web logs for some testing I was doing.  
import socket

target = "192.168.11.175"	# ip of web server
port = 80					# port of web server http only
links = {"/":0,"/twiki/bin/view/TWiki/IncludeTopicsAndWebPages":1} # links dictionary to track the links ( count of 0 means we still need to get it 1 = already got.  Added twiki for debugging
bad_chars = ("#","?") # characters to look for in lines to NOT process (keeps from getting the same page multiple times)



def get_data(link):  # get a page
	if links[link] == 0:
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		s.connect((target,port))
		s.send("GET "+link+" HTTP/1.0\r\n\r\n")
		print "Getting",link
		page = s.recv(999999)
		s.close()
		links[link] = 1 # update links dictionary so we don't get it again
		return page


def page_parser(html,parent): # parse the page
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
			
def main():
	while (0 in links.values()): # loop through our links until all are complete
		keys = links.keys()
		for link in keys:
			print "page_parser",link
			html = get_data(link)
			if html:
				try:
					page_parser(html,link)
				except:
					print "error"
	#print links
	return 0
	
if __name__ == '__main__':
	main()
