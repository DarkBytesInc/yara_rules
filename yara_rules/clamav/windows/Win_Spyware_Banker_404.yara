rule Win_Spyware_Banker_404
{
strings:
	$a0 = { 692387db6e76ca1fa26496019a24f1ef562db63cc31fa5f26bcafde34d704a56a34b446ceb3c96905a43b02c837e6f1bae40e2c61da325e07b9f3ce4e700963377199cc2f60f849adc9c08de524900e5dc8f5c2df3241c4873f046dd907d454f848321475b7cdf6d2f6c33e40e1a1f5121c2b12184a1166981dcfed32a18c3e6e235db3155acec5569bb9347075db30e0c6be95d67 }

condition:
	$a0
}

        