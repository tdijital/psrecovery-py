
class Event(object):
  
    def __init__(self):
        self._eventhandlers = []
  
    def __iadd__(self, handler):
        self._eventhandlers.append(handler)
        return self
  
    def __isub__(self, handler):
        self._eventhandlers.remove(handler)
        return self
  
    def __call__(self, *args, **keywargs):
        for eventhandler in self._eventhandlers:
            eventhandler(*args, **keywargs)