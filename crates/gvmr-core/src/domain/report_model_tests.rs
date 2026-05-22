use super::*;

#[test]
fn deserializes_report_envelope_with_top_level_fields() {
    let xml = r#"
        <report
            id="outer-report-id"
            content_type="text/xml"
            extension="xml"
            format_id="format-1"
            config_id="config-1"
        >
            <owner>
                <name>admin</name>
            </owner>
            <name>Example report</name>
            <comment>Example comment</comment>
            <creation_time>2026-05-08T10:00:00Z</creation_time>
            <modification_time>2026-05-08T11:00:00Z</modification_time>
            <writable>1</writable>
            <in_use>0</in_use>
            <task id="task-ref-1">
                <name>Task Ref</name>
            </task>
            <report_format id="format-ref-1">
                <name>XML</name>
            </report_format>
            <report id="inner-report-id">
                <scan_run_status>Done</scan_run_status>
                <timestamp>2026-05-08T12:00:00Z</timestamp>
                <scan_start>2026-05-08T09:00:00Z</scan_start>
                <scan_end>2026-05-08T10:00:00Z</scan_end>
                <timezone>UTC</timezone>
                <timezone_abbrev>UTC</timezone_abbrev>
            </report>
        </report>
    "#;

    let envelope: ReportEnvelope =
        quick_xml::de::from_str(xml).expect("report envelope should deserialize");

    assert_eq!(envelope.id.as_deref(), Some("outer-report-id"));
    assert_eq!(envelope.content_type.as_deref(), Some("text/xml"));
    assert_eq!(envelope.extension.as_deref(), Some("xml"));
    assert_eq!(envelope.format_id.as_deref(), Some("format-1"));
    assert_eq!(envelope.config_id.as_deref(), Some("config-1"));

    assert_eq!(envelope.owner.unwrap().name.as_deref(), Some("admin"));
    assert_eq!(envelope.name.as_deref(), Some("Example report"));
    assert_eq!(envelope.comment.as_deref(), Some("Example comment"));
    assert_eq!(
        envelope.creation_time.as_deref(),
        Some("2026-05-08T10:00:00Z")
    );
    assert_eq!(
        envelope.modification_time.as_deref(),
        Some("2026-05-08T11:00:00Z")
    );
    assert_eq!(envelope.writable.as_deref(), Some("1"));
    assert_eq!(envelope.in_use.as_deref(), Some("0"));

    let task = envelope.task.expect("expected top-level task ref");
    assert_eq!(task.id.as_deref(), Some("task-ref-1"));
    assert_eq!(task.name.as_deref(), Some("Task Ref"));

    let report_format = envelope
        .report_format
        .expect("expected top-level report format ref");
    assert_eq!(report_format.id.as_deref(), Some("format-ref-1"));
    assert_eq!(report_format.name.as_deref(), Some("XML"));

    assert_eq!(envelope.report.id.as_deref(), Some("inner-report-id"));
    assert_eq!(envelope.report.scan_run_status.as_deref(), Some("Done"));
    assert_eq!(
        envelope.report.timestamp.as_deref(),
        Some("2026-05-08T12:00:00Z")
    );
    assert_eq!(
        envelope.report.scan_start.as_deref(),
        Some("2026-05-08T09:00:00Z")
    );
    assert_eq!(
        envelope.report.scan_end.as_deref(),
        Some("2026-05-08T10:00:00Z")
    );
    assert_eq!(envelope.report.timezone.as_deref(), Some("UTC"));
    assert_eq!(envelope.report.timezone_abbrev.as_deref(), Some("UTC"));
}

#[test]
fn deserializes_inner_report_counts_and_task() {
    let xml = r#"
        <report id="outer-report-id">
            <report id="inner-report-id">
                <gmp>
                    <version>22.7</version>
                </gmp>
                <scan_run_status>Done</scan_run_status>
                <hosts>
                    <count>2</count>
                </hosts>
                <closed_cves>
                    <count>1</count>
                </closed_cves>
                <vulns>
                    <count>3</count>
                </vulns>
                <os>
                    <count>4</count>
                </os>
                <apps>
                    <count>5</count>
                </apps>
                <ssl_certs>
                    <count>6</count>
                </ssl_certs>
                <task id="task-1">
                    <name>Main task</name>
                    <comment>Main task comment</comment>
                    <target id="target-1">
                        <trash>0</trash>
                        <name>Main target</name>
                        <comment>Main target comment</comment>
                    </target>
                    <agent_group id="agent-group-1">
                        <trash>0</trash>
                        <name>Agent Group</name>
                        <comment>Agent comment</comment>
                    </agent_group>
                    <progress>100</progress>
                </task>
            </report>
        </report>
    "#;

    let envelope: ReportEnvelope =
        quick_xml::de::from_str(xml).expect("report envelope should deserialize");

    let report = envelope.report;

    assert_eq!(report.id.as_deref(), Some("inner-report-id"));
    assert_eq!(report.gmp.unwrap().version.as_deref(), Some("22.7"));
    assert_eq!(report.scan_run_status.as_deref(), Some("Done"));

    assert_eq!(report.hosts.unwrap().count.as_deref(), Some("2"));
    assert_eq!(report.closed_cves.unwrap().count.as_deref(), Some("1"));
    assert_eq!(report.vulns.unwrap().count.as_deref(), Some("3"));
    assert_eq!(report.os.unwrap().count.as_deref(), Some("4"));
    assert_eq!(report.apps.unwrap().count.as_deref(), Some("5"));
    assert_eq!(report.ssl_certs.unwrap().count.as_deref(), Some("6"));

    let task = report.task.expect("expected task");
    assert_eq!(task.id.as_deref(), Some("task-1"));
    assert_eq!(task.name.as_deref(), Some("Main task"));
    assert_eq!(task.comment.as_deref(), Some("Main task comment"));
    assert_eq!(task.progress.as_deref(), Some("100"));

    let target = task.target.expect("expected target");
    assert_eq!(target.id.as_deref(), Some("target-1"));
    assert_eq!(target.trash.as_deref(), Some("0"));
    assert_eq!(target.name.as_deref(), Some("Main target"));
    assert_eq!(target.comment.as_deref(), Some("Main target comment"));

    let agent_group = task.agent_group.expect("expected agent group");
    assert_eq!(agent_group.id.as_deref(), Some("agent-group-1"));
    assert_eq!(agent_group.trash.as_deref(), Some("0"));
    assert_eq!(agent_group.name.as_deref(), Some("Agent Group"));
    assert_eq!(agent_group.comment.as_deref(), Some("Agent comment"));
}

#[test]
fn deserializes_inner_report_counts_and_container_image_task() {
    let xml = r#"
        <report id="outer-report-id">
            <report id="inner-report-id">
                <gmp>
                    <version>22.7</version>
                </gmp>
                <scan_run_status>Done</scan_run_status>
                <hosts>
                    <count>2</count>
                </hosts>
                <closed_cves>
                    <count>1</count>
                </closed_cves>
                <vulns>
                    <count>3</count>
                </vulns>
                <os>
                    <count>4</count>
                </os>
                <apps>
                    <count>5</count>
                </apps>
                <ssl_certs>
                    <count>6</count>
                </ssl_certs>
                <task id="task-1">
                    <name>Main task</name>
                    <comment>Main task comment</comment>
                    <target id="target-1">
                        <trash>0</trash>
                        <name>Main target</name>
                        <comment>Main target comment</comment>
                    </target>
                    <oci_image_target id="pci-image-1">
                        <trash>0</trash>
                        <name>OCI Image Target</name>
                        <comment>OCI Image comment</comment>
                    </oci_image_target>
                    <progress>100</progress>
                </task>
            </report>
        </report>
    "#;

    let envelope: ReportEnvelope =
        quick_xml::de::from_str(xml).expect("report envelope should deserialize");

    let report = envelope.report;

    assert_eq!(report.id.as_deref(), Some("inner-report-id"));
    assert_eq!(report.gmp.unwrap().version.as_deref(), Some("22.7"));
    assert_eq!(report.scan_run_status.as_deref(), Some("Done"));

    assert_eq!(report.hosts.unwrap().count.as_deref(), Some("2"));
    assert_eq!(report.closed_cves.unwrap().count.as_deref(), Some("1"));
    assert_eq!(report.vulns.unwrap().count.as_deref(), Some("3"));
    assert_eq!(report.os.unwrap().count.as_deref(), Some("4"));
    assert_eq!(report.apps.unwrap().count.as_deref(), Some("5"));
    assert_eq!(report.ssl_certs.unwrap().count.as_deref(), Some("6"));

    let task = report.task.expect("expected task");
    assert_eq!(task.id.as_deref(), Some("task-1"));
    assert_eq!(task.name.as_deref(), Some("Main task"));
    assert_eq!(task.comment.as_deref(), Some("Main task comment"));
    assert_eq!(task.progress.as_deref(), Some("100"));

    let target = task.target.expect("expected target");
    assert_eq!(target.id.as_deref(), Some("target-1"));
    assert_eq!(target.trash.as_deref(), Some("0"));
    assert_eq!(target.name.as_deref(), Some("Main target"));
    assert_eq!(target.comment.as_deref(), Some("Main target comment"));

    let oci_image_target = task.oci_image_target.expect("expected OCI image target");
    assert_eq!(oci_image_target.id.as_deref(), Some("pci-image-1"));
    assert_eq!(oci_image_target.trash.as_deref(), Some("0"));
    assert_eq!(oci_image_target.name.as_deref(), Some("OCI Image Target"));
    assert_eq!(
        oci_image_target.comment.as_deref(),
        Some("OCI Image comment")
    );
}

#[test]
fn deserializes_filters_sort_ports_and_result_counts() {
    let xml = r#"
        <report id="outer-report-id">
            <report id="inner-report-id">
                <sort>
                    <field>
                        severity
                        <order>descending</order>
                    </field>
                </sort>
                <filters id="filter-1">
                    <term>severity&gt;=5</term>
                    <filter>first-filter</filter>
                    <filter>second-filter</filter>
                    <keywords>
                        <keyword>
                            <column>severity</column>
                            <relation>&gt;=</relation>
                            <value>5</value>
                        </keyword>
                    </keywords>
                </filters>
                <ports start="1" max="10">
                    <count>1</count>
                    <port>
                        80/tcp
                        <host>192.168.1.10</host>
                        <severity>5.0</severity>
                        <threat>Medium</threat>
                    </port>
                </ports>
                <result_count>
                    <full>10</full>
                    <filtered>8</filtered>
                    <critical>
                        <full>1</full>
                        <filtered>1</filtered>
                    </critical>
                    <high>
                        <full>2</full>
                        <filtered>2</filtered>
                    </high>
                    <medium>
                        <full>3</full>
                        <filtered>3</filtered>
                    </medium>
                    <low>
                        <full>4</full>
                        <filtered>2</filtered>
                    </low>
                </result_count>
                <severity>
                    <full>10.0</full>
                    <filtered>8.0</filtered>
                </severity>
            </report>
        </report>
    "#;

    let envelope: ReportEnvelope =
        quick_xml::de::from_str(xml).expect("report envelope should deserialize");

    let report = envelope.report;

    let sort = report.sort.expect("expected sort");
    let field = sort.field.expect("expected sort field");
    assert_eq!(field.order.as_deref(), Some("descending"));
    assert_eq!(field.text.as_deref().map(str::trim), Some("severity"));

    let filters = report.filters.expect("expected filters");
    assert_eq!(filters.id.as_deref(), Some("filter-1"));
    assert_eq!(filters.term.as_deref(), Some("severity>=5"));
    assert_eq!(filters.filter.len(), 2);
    assert_eq!(filters.filter[0], "first-filter");
    assert_eq!(filters.filter[1], "second-filter");

    let keywords = filters.keywords.expect("expected filter keywords");
    assert_eq!(keywords.keyword.len(), 1);
    assert_eq!(keywords.keyword[0].column.as_deref(), Some("severity"));
    assert_eq!(keywords.keyword[0].relation.as_deref(), Some(">="));
    assert_eq!(keywords.keyword[0].value.as_deref(), Some("5"));

    let ports = report.ports.expect("expected ports");
    assert_eq!(ports.start.as_deref(), Some("1"));
    assert_eq!(ports.max.as_deref(), Some("10"));
    assert_eq!(ports.count.as_deref(), Some("1"));
    assert_eq!(ports.port.len(), 1);
    assert_eq!(ports.port[0].text.as_deref().map(str::trim), Some("80/tcp"));
    assert_eq!(ports.port[0].host.as_deref(), Some("192.168.1.10"));
    assert_eq!(ports.port[0].severity.as_deref(), Some("5.0"));
    assert_eq!(ports.port[0].threat.as_deref(), Some("Medium"));

    let result_count = report.result_count.expect("expected result count");
    assert_eq!(result_count.full.as_deref(), Some("10"));
    assert_eq!(result_count.filtered.as_deref(), Some("8"));
    assert_eq!(result_count.critical.unwrap().full.as_deref(), Some("1"));
    assert_eq!(result_count.high.unwrap().filtered.as_deref(), Some("2"));
    assert_eq!(result_count.medium.unwrap().full.as_deref(), Some("3"));
    assert_eq!(result_count.low.unwrap().filtered.as_deref(), Some("2"));

    let severity = report.severity.expect("expected severity summary");
    assert_eq!(severity.full.as_deref(), Some("10.0"));
    assert_eq!(severity.filtered.as_deref(), Some("8.0"));
}

#[test]
fn deserializes_results_with_nvt_qod_refs_epss_and_host() {
    let xml = r#"
        <report id="outer-report-id">
            <report id="inner-report-id">
                <results start="1" max="100">
                    <result id="result-1">
                        <name>Example vulnerability</name>
                        <owner>
                            <name>admin</name>
                        </owner>
                        <modification_time>2026-05-08T11:00:00Z</modification_time>
                        <comment>Result comment</comment>
                        <creation_time>2026-05-08T10:00:00Z</creation_time>
                        <host>
                            192.168.1.10
                            <asset asset_id="asset-1"/>
                            <hostname>host.local</hostname>
                        </host>
                        <port>80/tcp</port>
                        <nvt oid="1.2.3.4">
                            <type>nvt</type>
                            <name>NVT name</name>
                            <family>General</family>
                            <cvss_base>5.0</cvss_base>
                            <severities score="5.0">
                                <severity type="cvss_base_v2">
                                    <origin>NVD</origin>
                                    <date>2026-05-08</date>
                                    <score>5.0</score>
                                    <value>AV:N/AC:L/Au:N/C:P/I:N/A:N</value>
                                </severity>
                            </severities>
                            <tags>summary=Example|impact=Example impact</tags>
                            <solution type="VendorFix">Update package</solution>
                            <epss>
                                <max_severity>
                                    <score>7.5</score>
                                    <percentile>0.9</percentile>
                                    <cve id="CVE-2026-0001">
                                        <severity>7.5</severity>
                                    </cve>
                                </max_severity>
                                <max_epss>
                                    <score>0.42</score>
                                    <percentile>0.99</percentile>
                                    <cve id="CVE-2026-0002">
                                        <severity>8.0</severity>
                                    </cve>
                                </max_epss>
                            </epss>
                            <refs>
                                <ref id="CVE-2026-0001" type="cve"/>
                                <ref id="BID-1" type="bid"/>
                            </refs>
                        </nvt>
                        <scan_nvt_version>2026-05-08</scan_nvt_version>
                        <threat>Medium</threat>
                        <severity>5.0</severity>
                        <qod>
                            <value>80</value>
                            <type>remote_active</type>
                        </qod>
                        <description>Description text</description>
                        <original_threat>Medium</original_threat>
                        <original_severity>5.0</original_severity>
                        <compliance>no</compliance>
                    </result>
                </results>
            </report>
        </report>
    "#;

    let envelope: ReportEnvelope =
        quick_xml::de::from_str(xml).expect("report envelope should deserialize");

    let results = envelope.report.results.expect("expected results");
    assert_eq!(results.start.as_deref(), Some("1"));
    assert_eq!(results.max.as_deref(), Some("100"));
    assert_eq!(results.result.len(), 1);

    let result = &results.result[0];

    assert_eq!(result.id.as_deref(), Some("result-1"));
    assert_eq!(result.name.as_deref(), Some("Example vulnerability"));
    assert_eq!(
        result.owner.as_ref().unwrap().name.as_deref(),
        Some("admin")
    );
    assert_eq!(result.port.as_deref(), Some("80/tcp"));
    assert_eq!(result.threat.as_deref(), Some("Medium"));
    assert_eq!(result.severity.as_deref(), Some("5.0"));
    assert_eq!(result.description.as_deref(), Some("Description text"));
    assert_eq!(result.original_threat.as_deref(), Some("Medium"));
    assert_eq!(result.original_severity.as_deref(), Some("5.0"));
    assert_eq!(result.compliance.as_deref(), Some("no"));

    let host = result.host.as_ref().expect("expected host");
    assert_eq!(host.text.as_deref().map(str::trim), Some("192.168.1.10"));
    assert_eq!(
        host.asset.as_ref().unwrap().asset_id.as_deref(),
        Some("asset-1")
    );
    assert_eq!(host.hostname.as_deref(), Some("host.local"));

    let qod = result.qod.as_ref().expect("expected qod");
    assert_eq!(qod.value.as_deref(), Some("80"));
    assert_eq!(qod.r#type.as_deref(), Some("remote_active"));

    let nvt = result.nvt.as_ref().expect("expected nvt");
    assert_eq!(nvt.oid.as_deref(), Some("1.2.3.4"));
    assert_eq!(nvt.r#type.as_deref(), Some("nvt"));
    assert_eq!(nvt.name.as_deref(), Some("NVT name"));
    assert_eq!(nvt.family.as_deref(), Some("General"));
    assert_eq!(nvt.cvss_base.as_deref(), Some("5.0"));
    assert_eq!(
        nvt.solution.as_ref().unwrap().r#type.as_deref(),
        Some("VendorFix")
    );
    assert_eq!(
        nvt.solution.as_ref().unwrap().text.as_deref(),
        Some("Update package")
    );

    let severities = nvt.severities.as_ref().expect("expected severities");
    assert_eq!(severities.score.as_deref(), Some("5.0"));
    assert_eq!(severities.severity.len(), 1);
    assert_eq!(
        severities.severity[0].r#type.as_deref(),
        Some("cvss_base_v2")
    );
    assert_eq!(severities.severity[0].origin.as_deref(), Some("NVD"));
    assert_eq!(severities.severity[0].score.as_deref(), Some("5.0"));

    let refs = nvt.refs.as_ref().expect("expected refs");
    assert_eq!(refs.reference.len(), 2);
    assert_eq!(refs.reference[0].id.as_deref(), Some("CVE-2026-0001"));
    assert_eq!(refs.reference[0].r#type.as_deref(), Some("cve"));

    let epss = nvt.epss.as_ref().expect("expected epss");
    let max_severity = epss.max_severity.as_ref().expect("expected max severity");
    assert_eq!(max_severity.score.as_deref(), Some("7.5"));
    assert_eq!(max_severity.percentile.as_deref(), Some("0.9"));
    assert_eq!(
        max_severity.cve.as_ref().unwrap().id.as_deref(),
        Some("CVE-2026-0001")
    );

    let max_epss = epss.max_epss.as_ref().expect("expected max epss");
    assert_eq!(max_epss.score.as_deref(), Some("0.42"));
    assert_eq!(max_epss.percentile.as_deref(), Some("0.99"));
    assert_eq!(
        max_epss.cve.as_ref().unwrap().id.as_deref(),
        Some("CVE-2026-0002")
    );
}

#[test]
fn deserializes_report_host_details() {
    let xml = r#"
        <report id="outer-report-id">
            <report id="inner-report-id">
                <host>
                    <ip>192.168.1.10</ip>
                    <asset asset_id="asset-1"/>
                    <start>2026-05-08T09:00:00Z</start>
                    <end>2026-05-08T10:00:00Z</end>
                    <port_count>
                        <page>2</page>
                    </port_count>
                    <result_count>
                        <page>3</page>
                        <critical>
                            <page>1</page>
                        </critical>
                        <hole deprecated="1">
                            <page>0</page>
                        </hole>
                        <high>
                            <page>2</page>
                        </high>
                        <warning deprecated="1">
                            <page>0</page>
                        </warning>
                        <medium>
                            <page>3</page>
                        </medium>
                        <info deprecated="1">
                            <page>0</page>
                        </info>
                        <low>
                            <page>4</page>
                        </low>
                        <log>
                            <page>5</page>
                        </log>
                        <false_positive>
                            <page>6</page>
                        </false_positive>
                    </result_count>
                    <detail>
                        <name>hostname</name>
                        <value>host.local</value>
                        <source>
                            <type>nvt</type>
                            <name>source name</name>
                            <description>source description</description>
                        </source>
                        <extra>extra detail</extra>
                    </detail>
                </host>
            </report>
        </report>
    "#;

    let envelope: ReportEnvelope =
        quick_xml::de::from_str(xml).expect("report envelope should deserialize");

    assert_eq!(envelope.report.hosts_detail.len(), 1);

    let host = &envelope.report.hosts_detail[0];

    assert_eq!(host.ip.as_deref(), Some("192.168.1.10"));
    assert_eq!(
        host.asset.as_ref().unwrap().asset_id.as_deref(),
        Some("asset-1")
    );
    assert_eq!(host.start.as_deref(), Some("2026-05-08T09:00:00Z"));
    assert_eq!(host.end.as_deref(), Some("2026-05-08T10:00:00Z"));
    assert_eq!(host.port_count.as_ref().unwrap().page.as_deref(), Some("2"));

    let result_count = host.result_count.as_ref().expect("expected result count");
    assert_eq!(result_count.page.as_deref(), Some("3"));
    assert_eq!(
        result_count.critical.as_ref().unwrap().page.as_deref(),
        Some("1")
    );
    assert_eq!(
        result_count.hole.as_ref().unwrap().deprecated.as_deref(),
        Some("1")
    );
    assert_eq!(
        result_count.high.as_ref().unwrap().page.as_deref(),
        Some("2")
    );
    assert_eq!(
        result_count.warning.as_ref().unwrap().deprecated.as_deref(),
        Some("1")
    );
    assert_eq!(
        result_count.medium.as_ref().unwrap().page.as_deref(),
        Some("3")
    );
    assert_eq!(
        result_count.info.as_ref().unwrap().deprecated.as_deref(),
        Some("1")
    );
    assert_eq!(
        result_count.low.as_ref().unwrap().page.as_deref(),
        Some("4")
    );
    assert_eq!(
        result_count.log.as_ref().unwrap().page.as_deref(),
        Some("5")
    );
    assert_eq!(
        result_count
            .false_positive
            .as_ref()
            .unwrap()
            .page
            .as_deref(),
        Some("6")
    );

    assert_eq!(host.detail.len(), 1);

    let detail = &host.detail[0];
    assert_eq!(detail.name.as_deref(), Some("hostname"));
    assert_eq!(detail.value.as_deref(), Some("host.local"));
    assert_eq!(detail.extra.as_deref(), Some("extra detail"));

    let source = detail.source.as_ref().expect("expected detail source");
    assert_eq!(source.r#type.as_deref(), Some("nvt"));
    assert_eq!(source.name.as_deref(), Some("source name"));
    assert_eq!(source.description.as_deref(), Some("source description"));
}
