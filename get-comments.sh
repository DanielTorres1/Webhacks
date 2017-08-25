#!/bin/bash
grep --color=never -ir '// ' * | egrep -v "header|footer|div|class" >> coments2.txt
grep --color=never -r '<!-- ' * | egrep -v "header|footer|div|class" >> coments2.txt
grep --color=never -r ' \-\->' * | egrep -v "header|footer|div|class" >> coments2.txt
cat coments2.txt | cut -d ":" -f2 | sort | uniq > coments.txt
rm coments2.txt
