rule Win_Downloader_Agent_34726
{
strings:
	$a0 = { a2f85d1b65e78955c4a87641852ddf2359a10c12afe8e3e1f688e5723d00db8bf3c1e6067503a291801a3b3cb2754f24c56c240e8535c36fb985ffca366b2ed3e285eb04430b93c616ccf9afc87c6e52fdc5252df73a716cbca9 }

condition:
	$a0
}

        
