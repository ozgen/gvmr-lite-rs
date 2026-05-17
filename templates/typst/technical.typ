#set page(
  paper: "a4",
  margin: (x: 18mm, y: 18mm),
  header: context {
    if counter(page).get().first() > 1 {
      align(left + horizon)[
        #text(size: 8pt, style: "italic")[Scan Report]
        #h(1fr)
        #text(size: 8pt)[#counter(page).display()]
      ]
    }
  },
  footer: context {
    align(center)[
      #text(size: 8pt, style: "italic")[
        #counter(page).display() / #counter(page).final().first()
      ]
    ]
  },
)

#set text(font: "Liberation Sans", size: 9pt)
#set par(justify: true, leading: 0.55em)
#set heading(numbering: "1.1")

#let severity-color(threat) = {
  let value = lower(str(threat))

  if value == "critical" {
    rgb("#8b0000")
  } else if value == "high" {
    rgb("#dc143c")
  } else if value == "medium" {
    rgb("#ff8c00")
  } else if value == "low" {
    rgb("#50a0c8")
  } else if value == "log" {
    rgb("#1e90ff")
  } else if value == "false positive" {
    rgb("#808080")
  } else {
    rgb("#646464")
  }
}

#let maybe-block(title, body) = {
  if body != none and str(body).trim() != "" [
    #v(6pt)
    *#title* \
    #body
  ]
}

#let finding-card(
  threat: [Unknown],
  severity: none,
  nvt: [Finding],
  qod: none,
  detection-result: none,
  summary: none,
  impact: none,
  solution: none,
  affected: none,
  insight: none,
  detection-method: none,
  references: (),
  return-link: none,
) = [
  #block(
    width: 100%,
    stroke: 0.6pt + severity-color(threat),
    inset: 0pt,
    below: 9pt,
  )[
    #block(
      width: 100%,
      fill: severity-color(threat),
      inset: 5pt,
    )[
      #text(fill: white, weight: "bold")[
        #threat
        #if severity != none and str(severity).trim() != "" [
          #h(1fr) (CVSS: #severity)
        ]
      ]
    ]

    #block(inset: 7pt)[
      *NVT:* #nvt

      #maybe-block("Summary", summary)

      #if qod != none and str(qod).trim() != "" [
        #v(6pt)
        *Quality of Detection (QoD):* #qod
      ]

      #maybe-block("Vulnerability Detection Result", detection-result)
      #maybe-block("Impact", impact)
      #maybe-block("Solution", solution)
      #maybe-block("Affected Software/OS", affected)
      #maybe-block("Vulnerability Insight", insight)
      #maybe-block("Vulnerability Detection Method", detection-method)

      #if references.len() > 0 [
        #v(6pt)
        *References* \
        #for ref in references [
          #if str(ref).starts-with("http://") or str(ref).starts-with("https://") [
            #link(ref)[#ref]
          ] else [
            #ref
          ]
          #linebreak()
        ]
      ]

      #if return-link != none [
        #v(6pt)
        #return-link
      ]
    ]
  ]
]

#let overview-table(rows) = [
  #table(
    columns: (1.9fr, 0.7fr, 0.8fr, 0.7fr, 0.7fr, 1fr),
    stroke: 0.4pt,
    inset: 4pt,
    align: center,
    [*Host*],
    [*High*],
    [*Medium*],
    [*Low*],
    [*Log*],
    [*False Positive*],
    ..rows
  )
]

#let service-table(rows) = [
  #table(
    columns: (2fr, 1fr),
    stroke: 0.4pt,
    inset: 4pt,
    align: left,
    [*Service (Port)*],
    [*Threat Level*],
    ..rows
  )
]

#align(center)[
  #text(size: 18pt)[Scan Report]
]

#v(12pt)

#align(center)[
  {{report_date}}
]

#v(12pt)

#align(center)[
  *Summary*
]

#v(4pt)

{{summary}}

#v(20pt)

= Contents

#outline(indent: auto)

#pagebreak()

= Result Overview <result-overview>

{{overview_table}}

#v(8pt)

{{filter_notes}}

{{host_authentications}}

#pagebreak()

= Results per Host <results-per-host>

{{results_per_host}}