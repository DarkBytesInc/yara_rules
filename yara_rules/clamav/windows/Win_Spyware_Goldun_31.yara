rule Win_Spyware_Goldun_31
{
strings:
	$a0 = { b831397bb8eaa26ee79dac39c83919786246a28184540a56f8e3c6fc1a11aafbeefea32ff9b7a16bb945ea0762ba426d9e8370fcb3e3ad649d97a756163a308231e8a403ed97fc8147471ae7a29d803583deff0f025d76f8ad0071e7cf561ac3 }

condition:
	$a0
}

        
