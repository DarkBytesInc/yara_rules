rule Win_Spyware_Banker_3980
{
strings:
	$a0 = { 4600a48115041fc48fa2b102870089cf7921c20dedad6b73731bb9dee6bfc3bfc077b99dc816e6e40db73641aee40d6af22dd582e56f202d600dd7202d720375c905ae41af5c905b7209adc907f1901bb7203b7b905eeee41b6f7096eeee0b76f71def73bdffffff6fbe79e7cf3de7cfbf3e7df9f7dfbce73fb79fbf022e6471124bd6cb65aad166b58f1df4 }

condition:
	$a0
}

        