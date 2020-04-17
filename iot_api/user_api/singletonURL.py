from iot_api.user_api.model import Params

class singletonURL(object):
    __instance = None

    def __new__(cls):
        if singletonURL.__instance is None:
            print("-----------------creating new instance-----------------------")
            singletonURL.__instance = object.__new__(cls)
            singletonURL.url = Params.get_url_base()
        return singletonURL.__instance
    
    def getParam(self):
        return self.url