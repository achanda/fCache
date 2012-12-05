import pyinotify
import httplib2
import redis
import socket
import fcntl
import struct

controller = 'http://12.133.183.82:8080'
path = '/wm/cachemanager/'
server = redis.Redis('localhost')
my_ip = '192.168.122.21'

def get_ip(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def query_controller(serverip,cacheip):
    url = controller + path + 'get,' + serverip + ',' + cacheip + '/json'
    response, content = httplib2.Http().request(url)
    print "URL: " + url
    return content

class Handler(pyinotify.ProcessEvent):
    def process_IN_CLOSE_WRITE(self,evt):
        filename = 'image.jpg'
        print "Event fired"
        f = open(filename,'rb')
        data = f.read()
        server_ip = server.get('server_ip')
        my_ip = get_ip('eth0')
        tempname = query_controller(server_ip,'192.168.122.21')
        temp = open(tempname,'wb')
        temp_index = data.split('\r\n\r\n')
        temp.write(temp_index[1])
        temp.close()
        print "Saved " + tempname 
        

handler = Handler()
wm = pyinotify.WatchManager()
notifier = pyinotify.Notifier(wm,handler)
wdd = wm.add_watch('image.jpg',pyinotify.IN_CLOSE_WRITE)
notifier.loop()

