rule Win_Downloader_Adload_70
{
strings:
	$a0 = { 82a0bcc56bcfc33aec4baad0a01dd8316132150017d873d3270fcd82833e2b94dcc35074d4d7f970c0a535adacf6ec46caa65d7992d803fb96ac1e01acc05a6eb56bf3b24344803eee6bf549b0bc3f7323fdddef867001a9b61141340b403dc577541c24a2bf0552eaec7a6df36f }

condition:
	$a0
}

        
