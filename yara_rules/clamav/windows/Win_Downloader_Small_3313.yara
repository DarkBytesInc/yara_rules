rule Win_Downloader_Small_3313
{
strings:
	$a0 = { 6ac0d4188ba51a3f4bd7e8e4272d933359ad3bd9e6fd534cb06f4db5d3ccc3d150759cede0995cc9db8d26eec4ff00b64e50447c63e5fd2a14721218fba87b43f51d41ed1d3311d3bb84e87aef4048f712491a7de44a92a35b67 }

condition:
	$a0
}

        
