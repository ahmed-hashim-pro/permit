# Terminal demo for the README. Regenerate with:  make demo
# Records the real CLI against the examples; nothing is staged.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1180
Set Height 600
Set Padding 18
Set Theme "GitHub Dark"
Set TypingSpeed 30ms

Hide
Type `export PATH=/opt/node/bin:$PATH PS1='$ ' && permit() { node /vhs/dist/src/cli.js "$@"; } && cd /vhs/examples/ua-sniff && clear`
Enter
Show

Type "permit diff before.json after.json --fixtures ../../fixtures/packages   # a patch release of a UA parser"
Enter
Sleep 4s

Type "echo exit $?"
Enter
Sleep 1.5s

Type "clear && cd ../event-stream"
Enter
Sleep 300ms

Type "permit diff before.json after.json --fixtures ../../fixtures/packages   # an event-stream-shaped upgrade"
Enter
Sleep 5s

Type "clear && cd ../monday && cat permit.json"
Enter
Sleep 2s

Type "permit diff before.json after.json --fixtures ../../fixtures/packages"
Enter
Sleep 5s
