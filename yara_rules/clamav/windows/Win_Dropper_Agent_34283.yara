rule Win_Dropper_Agent_34283
{
strings:
	$a0 = { 4851336b899c3848ca6329e3173e25f422396ab5588a15470d547324e85386b3141494b10ae70a6987870c3fe42eb9ebae25ccdf2a2d3b8f1d0d8e4f21fb699a6f316d66424306bd0a246a47cb4829983de104013c018c711b121ece3e54980712d798c572759c4644c6a3aff4c1f3efbd45710b2be9a6daffd3c5e4e9d7af8fc4980875c498aa154479ecf21596c8c9 }

condition:
	$a0
}

        