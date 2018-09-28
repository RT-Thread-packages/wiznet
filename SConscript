from building import *

cwd  = GetCurrentDir()

src  = Glob('src/*.c')
src += Glob('ioLibrary/Ethernet/*.c')
src += Glob('ioLibrary/Internet/DNS/*.c')

if GetDepend(['WIZ_USING_DHCP']):
    src += Glob('ioLibrary/Internet/DHCP/*.c')

if GetDepend(['WIZ_USING_W5500']):
    src += Glob('ioLibrary/Ethernet/W5500/*.c')
    
CPPPATH = [
cwd + '/inc',
cwd + '/ioLibrary',
cwd + '/ioLibrary/Ethernet',
cwd + '/ioLibrary/Internet',
]

group = DefineGroup('WIZnet', src, depend = ['PKG_USING_WIZNET'], CPPPATH = CPPPATH)

Return('group')
