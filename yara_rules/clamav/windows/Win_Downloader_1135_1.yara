rule Win_Downloader_1135_1
{
strings:
	$a0 = { 885c58d551c49f6cbe04e0f128b2e2e8ed3c9c248a581fe5b2de54bc1d457fc1d02c3958c5f6b00f8aaea9bee0ea2189e2dcd0f53e5b52b5551552301902ba6a1275d7b3095b0ffa930d542cb2a8b8ffc4e81f00b306d9140fc4b30d }

condition:
	$a0
}

        
