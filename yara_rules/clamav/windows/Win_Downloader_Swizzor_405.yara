rule Win_Downloader_Swizzor_405
{
strings:
	$a0 = { 44f80a7197c3bca1ce3df62c28028eeca7cd092279277f439693cd7d719e8f1affca6a1e1da50b35d8505b8ac7fa1a1375d76c44d561f00e587d0e56da6e5e64096ba23d3243668f228a079511880ed7fcbf4d78cc0d5cffa530 }

condition:
	$a0
}

        
