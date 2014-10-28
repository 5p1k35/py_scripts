from subprocess import Popen
from time import sleep
from ctypes import windll

browser1 = Popen(["C:/Program Files (x86)/Mozilla Firefox/firefox.exe","http://www.google.com"],shell=False)
browser2 = Popen(["C:/Program Files (x86)/Google/Chrome/Application/chrome.exe","http://google.com"],shell=False)
browser3 = Popen(["C:/Program Files/Internet Explorer/iexplore.exe","http://google.com"],shell=False)

sleep (20)

browser1.kill()
browser2.kill()
browser3.kill()
