rule Win_Downloader_Banload_377
{
strings:
	$a0 = { fedac2a93d9e684c7acab175cc2b695da9737f564a03535cfd0e85126c840832f41ced529bcaedebe02a1a50ce4ee0b120eeb4e55e2dfc42743a857fb27a9dfed341d7a1a4ec63f121b8287f44c882cc14d9c887ace28b606b72fd73d7936347d3fcbf94bb60202447 }

condition:
	$a0
}

        
