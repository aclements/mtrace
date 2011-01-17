import sys, re

BASEPATH = "/atmp/scale-linux/"
LXR = "http://lxr.linux.no/linux+v2.6.36"

tmpl = """
<html>
  <head>
    <style type="text/css">
      body{
        font-size: 80%;
        font-family: sans;
      }
      table {
        border: 1px solid #c5d7ef;
        border-collapse: collapse;
        font-size: 1em;
        background-color: #ffffff;
      }
      td {
        margin: 0px;
        padding: .35em 1em .25em .35em;
      }
      tr.odd > td {
        background-color: #ffffff;
      }
      tr.even > td {
        background-color: #e9e9e9;
      }
      tr.sum > td {
        border-top: 1px solid #c5d7ef;
        cursor: pointer;
      }
      tr.detail {
        display: none;
      }
      tr.detail > td {
        padding-left: 1em;
      }
      thead > tr > td {
        background-color: #c5d7ef;
        font-weight: bold;
        vertical-align: bottom;
      }
    </style>
    <script type="text/javascript">
      function shade(x) {
        for (x = x.nextSibling; x.nodeType != 1; x = x.nextSibling);
        if (x.style.display === "none" || x.style.display === "") {
          x.style.display = "table-row";
          state += " " + x.id;
        } else {
          x.style.display = "none";
          state = state.replace(" " + x.id, "");
        }
        document.getElementById("state").value = state;
      }
      var state = "";
      var stateSet = {};
      function getState() {
        state = document.getElementById("state").value;
        var ids = state.split(" ");
        for (var n in ids) if (ids[n]) stateSet[ids[n]] = 1;
      }
      function init(x) {
        if (stateSet[x])
          document.getElementById(x).style.display = "table-row";
      }
    </script>
  </head>
  <body>
    <input type="text" id="state" style="display:none" />
    <script type="text/javascript">getState()</script>
    HEADER
    <table style="width:75em">
      <col width="70%" />
      <col width="10%" />
      <col width="10%" />
      <col />
      <thead><tr><td>Label class</td><td>Locked stores</td><td>Locked accesses</td><td>Total accesses</td></tr></thead>
      HERE
    </table>
  </body>
</html>
"""

rowtmpl = """\
<tr class="%s sum" onclick="shade(this)"><td>+ %s</td><td>%s</td><td>%s</td><td>%s</td></tr>"""
detailtmpl = """\
<tr id="d%d" class="%s detail"><td colspan="4">
HERE
<script type="text/javascript">init("d%d")</script>
</td></tr>"""
lutabletmpl = """\
<table width="100%">
<col width="5%" /><col width="5%" /><col width="15%" /><col width="25%" /><col />
HERE
</table>"""

def makeTable(rows, title):
    out = []
    out.append('<thead><tr><td colspan="%d">%s</td></tr></thead>' %
               (len(rows[0]), title))
    for row in rows:
        out.append("<tr>" + "".join("<td>%s</td>" % c for c in row) + "</tr>")
    return "\n".join(out)

header = []
info = []
for l in sys.stdin:
    if not l.strip():
        continue
    elif l.startswith("#"):
        header.append(l[1:].strip())
    elif l.strip() == "--":
        detail = info[-1][2]
    elif l[0].isspace():
        parts = l.strip().split(None, 5)
        if parts[0] == "st":
            parts[0] = "<b>st</b>"
        if parts[4].startswith(BASEPATH):
            parts[4] = parts[4][len(BASEPATH):]
            if LXR:
                fname, line = parts[4].split(":")
                parts[4] = '<a href="%s/%s#L%s">%s</a>' % \
                    (LXR, fname, line, parts[4])
        detail.append(parts)
    else:
        m = re.match("(.*) ([0-9]+%) +([0-9]+%) +([0-9]+)$", l)
        info.append(((m.group(1).strip(),) + m.group(2,3,4), [], []))
        detail = info[-1][1]

table = []
for (n, (lock, locked, unlocked)) in enumerate(info):
    cls = "even" if n%2 else "odd"
    table.append(rowtmpl % ((cls,) + lock))
    if locked or unlocked:
        lutable = []
        if locked:
            lutable.append(makeTable(locked, "Locked"))
        if unlocked:
            lutable.append(makeTable(unlocked, "Unlocked"))
        detail = lutabletmpl.replace("HERE", "\n".join(lutable))
    else:
        detail = ""
    table.append((detailtmpl % (n, cls, n)).replace("HERE", detail))

out = tmpl
out = out.replace("HEADER", "\n".join("<p>%s</p>" % h for h in header))
out = out.replace("HERE", "\n".join(table))
print out
