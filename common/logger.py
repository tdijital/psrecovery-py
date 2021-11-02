"""Just a basic logging class that handles multiple streams."""

class Logger(object):
    streams = []

    @staticmethod
    def log(msg):
        if (len(Logger.streams) == 0):
            print(msg)
        for stream in Logger.streams:
            stream.write(str(msg)+"\n")
            stream.flush()

    def remove_stream(stream):
        for _stream in Logger.streams:
            if _stream is stream:
                Logger.streams.remove(_stream)
                return