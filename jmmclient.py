import sys

from suds.client import Client
from suds.bindings import binding
from suds.sax.element import Element
from suds.transport.http import HttpTransport
from suds.plugin import MessagePlugin
from base64 import b64encode

from wcf.xml2records import XMLParser
from wcf.records import dump_records
from wcf.records import Record, print_records

import io

JMMServer_Address = "localhost"
JMMServer_Port = "8111"


class HttpAuthenticatedBinary(HttpTransport):
    """
    Provides basic http authentication for servers that don't follow
    the specified challenge / response model.  This implementation
    appends the I{Authorization} http header with base64 encoded
    credentials on every http request.
    """

    def open(self, request):
        self.addcredentials(request)
        return HttpTransport.open(self, request)

    def send(self, request):
        self.addcredentials(request)
        r = XMLParser.parse(request.message.decode('ascii'))
        data = dump_records(r)
        request.message = data
        request.headers['Content-Type'] = 'application/soap+msbin1'
        # request.message = request.message()
        return HttpTransport.send(self, request)

    def addcredentials(self, request):
        credentials = self.credentials()
        if not (None in credentials):
            encoded = b64encode(':'.join(credentials).encode('utf-8')).decode("ascii")
            basic = 'Basic %s' % encoded
            request.headers['Authorization'] = basic

    def credentials(self):
        return (self.options.username, self.options.password)


class BinaryMessagePlugin(MessagePlugin):
    def marshalled(self, context):
        body = context.envelope.getChild('Body')
        foo = body[0]
        foo.set('xmlns', 'http://tempuri.org/')

    # def sending(self, context):
    #     r = XMLParser.parse(context.envelope.decode('ascii'))
    #     data = dump_records(r)
    #     context.envelope = data

    def received(self, context):
        body = context.reply
        with io.BytesIO(body) as f, io.StringIO() as s:
            records = Record.parse(f)
            print_records(records, fp=s)
            context.reply = str(s.getvalue())
            s.close()


def call_service(action, address=JMMServer_Address, port=JMMServer_Port):
    binding.envns = ('s', 'http://www.w3.org/2003/05/soap-envelope')
    client = Client(
        format_url(address, port),
        headers={'Content-Type': 'application/soap+msbin1'},
        transport=HttpAuthenticatedBinary(),
        plugins=[BinaryMessagePlugin()]
    )

    ssnns = ('a', 'http://www.w3.org/2005/08/addressing')
    element_action = Element('Action', ns=ssnns).setText('http://tempuri.org/IJMMServer/{0}'.format(action))
    element_action.set('s:mustUnderstand', "1")
    element_reply_to = Element('ReplyTo', ns=ssnns)
    element_address = Element('Address', ns=ssnns).setText('http://www.w3.org/2005/08/addressing/anonymous')
    element_reply_to.insert(element_address, 0)
    element_to = Element('To', ns=ssnns).setText('http://{0}:{1}/JMMServerBinary'.format(address, port))
    element_to.set('s:mustUnderstand', "1")
    client.set_options(soapheaders=(element_action, element_reply_to, element_to))
    func = getattr(client.service, action)
    func()
    # print(result)


def format_url(address=JMMServer_Address, port=JMMServer_Port):
    return 'http://{0}:{1}/JMMServerBinary?singleWsdl'.format(address, port)


def scan_drop_folders():
    call_service('ScanDropFolders', JMMServer_Address, JMMServer_Port)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        JMMServer_Address = sys.argv[1]
        JMMServer_Port = sys.argv[2]
    # Useful services: GetServerStatus, ScanDropFolders, RescanUnlinkedFiles
    call_service('ScanDropFolders', JMMServer_Address, JMMServer_Port)
