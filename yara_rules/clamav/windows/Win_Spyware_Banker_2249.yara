rule Win_Spyware_Banker_2249
{
strings:
	$a0 = { 336448a7ec285fe8d624ff1beb92205139c69543323cf91599962d7c8f65a90b095c280e350f3e767e3152e559e83e9b445873336fc43dab8530b0e7e827bfbeb02cc3b9dd8229bdbc21eb5cf6f1beecf907ed59891494611efbb3d7bd732b89ba6bd070a82d545ccd3077744ad28b56216a6760d139ddf307f5fe2bc5f1b5627b8f109a18df3e730d7b9caa8a09b9bbfb768c0aceac }

condition:
	$a0
}

        