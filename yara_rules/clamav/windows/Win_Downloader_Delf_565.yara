rule Win_Downloader_Delf_565
{
strings:
	$a0 = { 068df267d77da32ca0de8bb4e8406d0225cdc1ee75d7389d11effb8eba68216b089aaf2a5ccf988ae8fa1e39c9e996103439a4dbbc8021fad52ecf7f56eafa93574adddd427b3ce8b13a5756b5931fc10eefdeccddceeddae9c398e8b139e2f9d34acaa4c73bf65dc10bb84061432017e4572ae4a0e2ed721dc0490016c8e1cf }

condition:
	$a0
}

        
