rule Win_Downloader_1359_1
{
strings:
	$a0 = { dbcc3e05052705c0d37de4fb50cc172a64bb1c5bacf4a245155faa47103354376fa969a859e4acfb12f548034322ea64e6c76c0d057bb6b6b2565dfcdd60acf69323832d6affb260b1a6caf28b0dc8a08b7ccbe630359b3ce444506aff1f4198ed5852e5f9cf }

condition:
	$a0
}

        
