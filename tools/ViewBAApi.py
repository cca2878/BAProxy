import json
from typing import Optional
from mitmproxy import contentviews, flow, http
from tools.BACryptor import BACryptor
from tools.FlowUtils import is_ba_api


class ViewBAApi(contentviews.View):
    name = "BA-Api"

    def __call__(self, data: bytes, *, content_type: Optional[str] = None, flow: Optional[flow.Flow] = None,
                 http_message: Optional[http.Message] = None, **unknown_metadata) -> contentviews.TViewResult:
        if not is_ba_api(flow):
            return "[Ori]Unknown", contentviews.format_text(http_message.content)

        http_type = type(http_message).__name__
        if http_type == "Request":
            return self.handle_request(content_type, http_message)
        elif http_type == "Response":
            return self.handle_response(content_type, http_message)

        return "[Ori]BA_Unknown", contentviews.format_text(http_message.content)

    def handle_request(self, content_type, http_message):
        if content_type == "multipart/form-data":
            return self.handle_multipart_form(http_message)
        else:
            return "BA_Unknown", contentviews.format_text(http_message.content)

    def handle_response(self, content_type, http_message):
        if content_type == "application/json":
            return "[Plain]BA_Json", contentviews.format_dict(json.loads(http_message.raw_content.decode()))
        elif content_type == "text/plain":
            return self.handle_text_plain(http_message)
        else:
            return "[Ori]BA_Unknown", contentviews.format_text(http_message.content)

    def handle_multipart_form(self, http_message):
        dict_data = http_message.multipart_form
        ret_dict = {"Part[protocol]": dict_data.get(b'protocol', b'').decode(),
                    "Part[encode]": dict_data.get(b'encode', b'').decode(), 'Part[packet]': ''}
        if dict_data.get(b'encode', b'False') == b'True':
            ret_dict['Part[packet]'] = json.dumps(BACryptor().decrypt(dict_data.get(b'packet', b'')), indent=2)
            return "[Crypt]BA_MultiPartForm", contentviews.format_dict(ret_dict)
        else:
            ret_dict['Part[packet]'] = dict_data.get(b'packet', b'').decode()
            return "[Plain]BA_MultiPartForm", contentviews.format_dict(ret_dict)

    def handle_text_plain(self, http_message):
        decrypted = BACryptor().decrypt(http_message.raw_content, True)
        decrypted['packet'] = json.loads(decrypted.get('packet', '{}'))
        decrypted = json.dumps(decrypted, indent=2)
        return "[Crypt]BA_Json", contentviews.format_text(decrypted)

    def render_priority(self, data: bytes, *, content_type: Optional[str] = None, flow: Optional[flow.Flow] = None,
                        http_message: Optional[http.Message] = None, **unknown_metadata) -> float:
        if is_ba_api(flow) and content_type in ("multipart/form-data", "application/json", "text/plain"):
            return 2
        return 0

# class ViewBCRMsgPack(contentviews.msgpack.ViewMsgPack):
#     name = "BCR msgpack"
#
#     def __call__(
#         self,
#         data: bytes,
#         *,
#         content_type: Optional[str] = None,
#         flow: Optional[flow.Flow] = None,
#         http_message: Optional[http.Message] = None,
#         **unknown_metadata,
#     ) -> contentviews.TViewResult:
#         if flow.request.query.get('format', '') == 'json':
#             decrypted = json.loads(data)
#             return f"BCR msgpack(json_plain)", contentviews.msgpack.format_msgpack(decrypted)
#         else:
#             decryptor = BCRCryptor()
#             decrypted = decryptor.decrypt(data)
#             return f"BCR msgpack(key={decryptor.get_key(data)})", contentviews.msgpack.format_msgpack(decrypted)
#
#     def render_priority(
#         self,
#         data: bytes,
#         *,
#         content_type: Optional[str] = None,
#         flow: Optional[flow.Flow] = None,
#         http_message: Optional[http.Message] = None,
#         **unknown_metadata,
#     ) -> float:
#         if is_pcr_api(flow):
#             return 2
#         return 0
