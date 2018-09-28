from building import *

cwd  = GetCurrentDir()

src  = Glob('src/*.c')
src += Glob('iolibrary/Ethernet/*.c')
src += Glob('iolibrary/Internet/DNS/*.c')

if GetDepend(['WIZ_USING_DHCP']):
    src += Glob('iolibrary/Internet/DHCP/*.c')

if GetDepend(['WIZ_USING_W5500']):
    src += Glob('iolibrary/Ethernet/W5500/*.c')
    
CPPPATH = [
cwd + '/inc',
cwd + '/iolibrary',
cwd + '/iolibrary/Ethernet',
cwd + '/iolibrary/Internet',
]

group = DefineGroup('WIZnet', src, depend = ['PKG_USING_WIZNET'], CPPPATH = CPPPATH)

Return('group')
