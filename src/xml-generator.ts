import { writeFileSync } from 'fs';
import { join } from 'path';

interface XMLGeneratorConfig {
  filename: string;
  totalRecords: number;
  format: 'burp' | 'nessus' | 'generic' | 'project' | 'deep-nested';
  options?: {
    rootElement?: string;
    includeAttributes?: boolean;
    includeCDATA?: boolean;
    nestingDepth?: number;
  };
}

interface BurpIssue {
  serialNumber: string;
  type: string;
  name: string;
  host: string;
  ip: string;
  path: string;
  location: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  confidence: 'Tentative' | 'Firm' | 'Certain';
  issueBackground: string;
  issueDetail: string;
  requestMethod: 'GET' | 'POST' | 'PUT' | 'DELETE';
  responseStatus: string;
}

interface NessusItem {
  port: number;
  protocol: 'tcp' | 'udp';
  severity: '0' | '1' | '2' | '3' | '4';
  pluginID: string;
  pluginName: string;
  description: string;
  solution: string;
  riskFactor: 'None' | 'Low' | 'Medium' | 'High' | 'Critical';
}

class XMLGenerator {
  private generateUniqueId(): string {
    return Math.floor(Math.random() * 9000000000000000000 + 1000000000000000000).toString();
  }

  private generateRandomIP(): string {
    return `${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 254) + 1}`;
  }

  private generateRandomMAC(): string {
    return Array.from({ length: 6 }, () =>
      Math.floor(Math.random() * 256)
        .toString(16)
        .padStart(2, '0')
        .toUpperCase()
    ).join(':');
  }

  private getRandomChoice<T>(choices: T[]): T {
    return choices[Math.floor(Math.random() * choices.length)];
  }

  private generateBurpIssue(): BurpIssue {
    const vulnerabilityTypes = [
      'SQL injection',
      'XSS vulnerability',
      'Command injection',
      'Open Redirect',
      'CSRF vulnerability',
      'Information disclosure',
      'Authentication bypass',
      'Directory traversal',
    ];

    const domains = ['example.com', 'testsite.org', 'webapp.net', 'api.service.com'];
    const paths = ['/api', '/search', '/login', '/users', '/admin', '/dashboard'];
    const parameters = ['id', 'q', 'user', 'token', 'search', 'filter'];

    const vulnType = this.getRandomChoice(vulnerabilityTypes);
    const domain = this.getRandomChoice(domains);
    const path = this.getRandomChoice(paths);
    const parameter = this.getRandomChoice(parameters);

    return {
      serialNumber: this.generateUniqueId(),
      type: Math.floor(Math.random() * 1000000 + 7000000).toString(),
      name: vulnType,
      host: `https://${domain}`,
      ip: this.generateRandomIP(),
      path: path,
      location: `${path}?${parameter}=${Math.floor(Math.random() * 100)}`,
      severity: this.getRandomChoice(['Low', 'Medium', 'High', 'Critical']),
      confidence: this.getRandomChoice(['Tentative', 'Firm', 'Certain']),
      issueBackground: `${vulnType} found in application`,
      issueDetail: `Parameter ${parameter} is vulnerable to ${vulnType}`,
      requestMethod: this.getRandomChoice(['GET', 'POST', 'PUT', 'DELETE']),
      responseStatus: this.getRandomChoice([
        '200 OK',
        '302 Found',
        '403 Forbidden',
        '500 Internal Server Error',
      ]),
    };
  }

  private generateNessusItem(): NessusItem {
    const pluginNames = [
      'Target Credential Status by Authentication Protocol',
      'SSH Rate Limited Device',
      'SSL Certificate Verification',
      'HTTP Server Security Headers',
      'Weak Cipher Suites',
      'Operating System Detection',
      'Service Detection',
    ];

    return {
      port: Math.floor(Math.random() * 65535) + 1,
      protocol: this.getRandomChoice(['tcp', 'udp']),
      severity: this.getRandomChoice(['0', '1', '2', '3', '4']),
      pluginID: Math.floor(Math.random() * 900000 + 100000).toString(),
      pluginName: this.getRandomChoice(pluginNames),
      description:
        'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.',
      solution: 'Update the affected software to the latest version or apply vendor patches.',
      riskFactor: this.getRandomChoice(['None', 'Low', 'Medium', 'High', 'Critical']),
    };
  }

  private generateBurpXML(config: XMLGeneratorConfig): string {
    const timestamp = new Date().toUTCString();
    const burpVersion = '2024.12.5';

    let xml = `<?xml version="1.0" encoding="UTF-8"?>\n`;
    xml += `<issues burpVersion="${burpVersion}" exportTime="${timestamp}">\n`;

    for (let i = 0; i < config.totalRecords; i++) {
      const issue = this.generateBurpIssue();

      xml += `  <issue>\n`;
      xml += `    <serialNumber>${issue.serialNumber}</serialNumber>\n`;
      xml += `    <type>${issue.type}</type>\n`;
      xml += `    <name><![CDATA[${issue.name}]]></name>\n`;
      xml += `    <host ip="${issue.ip}">${issue.host}</host>\n`;
      xml += `    <path><![CDATA[${issue.path}]]></path>\n`;
      xml += `    <location><![CDATA[${issue.location}]]></location>\n`;
      xml += `    <severity>${issue.severity}</severity>\n`;
      xml += `    <confidence>${issue.confidence}</confidence>\n`;
      xml += `    <issueBackground><![CDATA[${issue.issueBackground}]]></issueBackground>\n`;
      xml += `    <issueDetail><![CDATA[${issue.issueDetail}]]></issueDetail>\n`;

      // Add deeply nested vulnerability analysis
      xml += `    <analysis>\n`;
      xml += `      <classification>\n`;
      xml += `        <category type="primary">${this.getRandomChoice(['injection', 'xss', 'csrf', 'auth'])}</category>\n`;
      xml += `        <subcategory>\n`;
      xml += `          <level1>${this.getRandomChoice(['sql', 'nosql', 'ldap', 'xpath'])}</level1>\n`;
      xml += `          <level2>\n`;
      xml += `            <technique>${this.getRandomChoice(['union', 'boolean', 'time', 'error'])}</technique>\n`;
      xml += `            <complexity level="${this.getRandomChoice(['low', 'medium', 'high'])}">\n`;
      xml += `              <factors>\n`;
      xml += `                <authentication required="${Math.random() > 0.5}">${this.getRandomChoice(['none', 'basic', 'session'])}</authentication>\n`;
      xml += `                <privileges>${this.getRandomChoice(['anonymous', 'user', 'admin'])}</privileges>\n`;
      xml += `                <network>\n`;
      xml += `                  <access>${this.getRandomChoice(['local', 'adjacent', 'network'])}</access>\n`;
      xml += `                  <encryption>${Math.random() > 0.3}</encryption>\n`;
      xml += `                </network>\n`;
      xml += `              </factors>\n`;
      xml += `            </complexity>\n`;
      xml += `          </level2>\n`;
      xml += `        </subcategory>\n`;
      xml += `      </classification>\n`;
      xml += `      <impact>\n`;
      xml += `        <confidentiality score="${Math.floor(Math.random() * 10)}">\n`;
      xml += `          <dataTypes>\n`;
      xml += `            <type sensitive="${Math.random() > 0.5}">user_data</type>\n`;
      xml += `            <type sensitive="${Math.random() > 0.5}">system_config</type>\n`;
      xml += `          </dataTypes>\n`;
      xml += `        </confidentiality>\n`;
      xml += `        <integrity score="${Math.floor(Math.random() * 10)}" />\n`;
      xml += `        <availability score="${Math.floor(Math.random() * 10)}" />\n`;
      xml += `      </impact>\n`;
      xml += `    </analysis>\n`;

      xml += `    <requestresponse>\n`;
      xml += `      <request method="${issue.requestMethod}" base64="false"><![CDATA[${issue.requestMethod} ${issue.location} HTTP/1.1]]></request>\n`;
      xml += `      <response base64="false"><![CDATA[HTTP/1.1 ${issue.responseStatus}]]></response>\n`;
      xml += `    </requestresponse>\n`;
      xml += `  </issue>\n`;
    }

    xml += `</issues>\n`;
    return xml;
  }

  private generateNessusXML(config: XMLGeneratorConfig): string {
    const hostIP = this.generateRandomIP();
    const macAddress = this.generateRandomMAC();

    let xml = `<?xml version="1.0" encoding="UTF-8"?>\n`;
    xml += `<NessusClientData_v2>\n`;
    xml += `  <Report name="Security_Scan" xmlns:cm="http://www.nessus.org/cm">\n`;
    xml += `    <ReportHost name="${hostIP}">\n`;
    xml += `      <HostProperties>\n`;
    xml += `        <tag name="mac-address">${macAddress}</tag>\n`;
    xml += `        <tag name="host-ip">${hostIP}</tag>\n`;
    xml += `        <tag name="operating-system">Linux Ubuntu 20.04</tag>\n`;
    xml += `        <tag name="system-type">general-purpose</tag>\n`;
    xml += `        <tag name="Credentialed_Scan">true</tag>\n`;
    xml += `      </HostProperties>\n\n`;

    for (let i = 0; i < config.totalRecords; i++) {
      const item = this.generateNessusItem();

      xml += `      <ReportItem port="${item.port}" protocol="${item.protocol}" severity="${item.severity}" `;
      xml += `pluginID="${item.pluginID}" pluginName="${item.pluginName}">\n`;
      xml += `        <description>${item.description}</description>\n`;
      xml += `        <solution>${item.solution}</solution>\n`;
      xml += `        <risk_factor>${item.riskFactor}</risk_factor>\n`;
      xml += `        <plugin_output>Detected service on port ${item.port}/${item.protocol}</plugin_output>\n`;
      xml += `      </ReportItem>\n`;
    }

    xml += `    </ReportHost>\n`;
    xml += `  </Report>\n`;
    xml += `</NessusClientData_v2>\n`;
    return xml;
  }

  private generateGenericXML(config: XMLGeneratorConfig): string {
    const rootElement = config.options?.rootElement || 'data';
    const includeAttributes = config.options?.includeAttributes ?? true;
    const includeCDATA = config.options?.includeCDATA ?? false;

    let xml = `<?xml version="1.0" encoding="UTF-8"?>\n`;
    xml += `<${rootElement}${includeAttributes ? ` version="1.0" generated="${new Date().toISOString()}"` : ''}>\n`;

    for (let i = 0; i < config.totalRecords; i++) {
      xml += `  <record id="${i + 1}"${includeAttributes ? ` index="${i}"` : ''}>\n`;
      xml += `    <name>${includeCDATA ? '<![CDATA[' : ''}Record_${i.toString().padStart(6, '0')}${includeCDATA ? ']]>' : ''}</name>\n`;
      xml += `    <value>${Math.floor(Math.random() * 1000)}</value>\n`;
      xml += `    <category>${this.getRandomChoice(['A', 'B', 'C', 'D'])}</category>\n`;
      xml += `    <active>${Math.random() > 0.5}</active>\n`;
      xml += `    <metadata>\n`;
      xml += `      <created>${new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString()}</created>\n`;
      xml += `      <tags>\n`;
      xml += `        <tag>tag_${i % 5}</tag>\n`;
      xml += `        <tag>category_${this.getRandomChoice(['alpha', 'beta', 'gamma'])}</tag>\n`;
      xml += `      </tags>\n`;
      xml += `    </metadata>\n`;
      xml += `  </record>\n`;
    }

    xml += `</${rootElement}>\n`;
    return xml;
  }

  private generateProjectXML(config: XMLGeneratorConfig): string {
    let xml = `<?xml version="1.0" encoding="UTF-8"?>\n`;
    xml += `<project version="1.0" type="FEDRAMP_REV_5">\n`;
    xml += `  <meta>\n`;
    xml += `    <name><![CDATA[Test Security Project]]></name>\n`;
    xml += `    <color>#3B82F6</color>\n`;
    xml += `    <printApplicability>true</printApplicability>\n`;
    xml += `    <cannedText>false</cannedText>\n`;
    xml += `  </meta>\n`;
    xml += `  <system>\n`;
    xml += `    <systemName><![CDATA[Test Information System]]></systemName>\n`;
    xml += `    <systemShortName>TIS</systemShortName>\n`;
    xml += `    <packageId>TIS-${this.generateUniqueId().slice(0, 8)}</packageId>\n`;
    xml += `    <authorizationType>ATO</authorizationType>\n`;
    xml += `    <status>OPERATIONAL</status>\n`;
    xml += `  </system>\n`;
    xml += `  <controls>\n`;

    for (let i = 0; i < config.totalRecords; i++) {
      const controlId = `AC-${(i + 1).toString().padStart(2, '0')}`;
      xml += `    <control id="${controlId}">\n`;
      xml += `      <title><![CDATA[Access Control ${i + 1}]]></title>\n`;
      xml += `      <description><![CDATA[This control addresses access control requirements for the system.]]></description>\n`;
      xml += `      <implementationStatus>${this.getRandomChoice(['IMPLEMENTED', 'PARTIALLY_IMPLEMENTED', 'PLANNED', 'NOT_APPLICABLE'])}</implementationStatus>\n`;
      xml += `      <requirements>\n`;
      xml += `        <requirement id="${controlId}-1">\n`;
      xml += `          <statement><![CDATA[The system shall implement access control policies.]]></statement>\n`;
      xml += `          <implementationGuidance><![CDATA[Implement role-based access control mechanisms.]]></implementationGuidance>\n`;
      xml += `        </requirement>\n`;
      xml += `      </requirements>\n`;
      xml += `    </control>\n`;
    }

    xml += `  </controls>\n`;
    xml += `</project>\n`;
    return xml;
  }

  private generateDeepNestedXML(config: XMLGeneratorConfig): string {
    let xml = `<?xml version="1.0" encoding="UTF-8"?>\n`;
    xml += `<organization id="ORG-${this.generateUniqueId().slice(0, 8)}" type="enterprise">\n`;
    xml += `  <metadata created="${new Date().toISOString()}" version="2.1">\n`;
    xml += `    <generator>XML Deep Nesting Generator</generator>\n`;
    xml += `    <description><![CDATA[Complex hierarchical data with multiple navigation paths]]></description>\n`;
    xml += `  </metadata>\n`;

    for (let i = 0; i < config.totalRecords; i++) {
      const deptId = `DEPT-${i.toString().padStart(3, '0')}`;
      xml += `  <departments>\n`;
      xml += `    <department id="${deptId}" active="${Math.random() > 0.2}">\n`;
      xml += `      <info>\n`;
      xml += `        <name><![CDATA[${this.getRandomChoice(['Engineering', 'Security', 'Operations', 'Finance', 'Legal', 'HR'])} Department ${i + 1}]]></name>\n`;
      xml += `        <location>\n`;
      xml += `          <building>${this.getRandomChoice(['North', 'South', 'East', 'West'])} Building</building>\n`;
      xml += `          <floor level="${Math.floor(Math.random() * 20) + 1}">\n`;
      xml += `            <zones>\n`;
      xml += `              <zone type="restricted" clearance="${this.getRandomChoice(['PUBLIC', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'])}">\n`;
      xml += `                <access>\n`;
      xml += `                  <methods>\n`;
      xml += `                    <method type="card" required="true">\n`;
      xml += `                      <validation>\n`;
      xml += `                        <primary algorithm="AES256">${this.generateUniqueId().slice(0, 16)}</primary>\n`;
      xml += `                        <secondary algorithm="RSA2048">${this.generateUniqueId().slice(0, 32)}</secondary>\n`;
      xml += `                        <biometric>\n`;
      xml += `                          <fingerprint enabled="${Math.random() > 0.3}" />\n`;
      xml += `                          <retinal enabled="${Math.random() > 0.7}" />\n`;
      xml += `                          <facial enabled="${Math.random() > 0.5}" />\n`;
      xml += `                        </biometric>\n`;
      xml += `                      </validation>\n`;
      xml += `                    </method>\n`;
      xml += `                  </methods>\n`;
      xml += `                </access>\n`;
      xml += `              </zone>\n`;
      xml += `            </zones>\n`;
      xml += `          </floor>\n`;
      xml += `        </location>\n`;
      xml += `      </info>\n`;

      // Personnel branch
      xml += `      <personnel>\n`;
      xml += `        <management>\n`;
      xml += `          <directors>\n`;
      xml += `            <director id="DIR-${i}-1" level="senior">\n`;
      xml += `              <profile>\n`;
      xml += `                <personal>\n`;
      xml += `                  <name>Director ${i + 1}</name>\n`;
      xml += `                  <clearance level="${this.getRandomChoice(['SECRET', 'TOP_SECRET'])}">\n`;
      xml += `                    <validations>\n`;
      xml += `                      <background completed="${new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]}" />\n`;
      xml += `                      <polygraph status="${this.getRandomChoice(['PASSED', 'PENDING', 'FAILED'])}" />\n`;
      xml += `                    </validations>\n`;
      xml += `                  </clearance>\n`;
      xml += `                </personal>\n`;
      xml += `                <access>\n`;
      xml += `                  <systems>\n`;
      xml += `                    <system name="financial" permissions="read,write,delete" />\n`;
      xml += `                    <system name="hr" permissions="read,write" />\n`;
      xml += `                    <system name="security" permissions="read" />\n`;
      xml += `                  </systems>\n`;
      xml += `                </access>\n`;
      xml += `              </profile>\n`;
      xml += `            </director>\n`;
      xml += `          </directors>\n`;
      xml += `        </management>\n`;
      xml += `      </personnel>\n`;

      // Technology branch
      xml += `      <technology>\n`;
      xml += `        <infrastructure>\n`;
      xml += `          <networks>\n`;
      xml += `            <network type="production" vlan="${Math.floor(Math.random() * 4000) + 100}">\n`;
      xml += `              <subnets>\n`;
      xml += `                <subnet cidr="${this.generateRandomIP()}/24">\n`;
      xml += `                  <security>\n`;
      xml += `                    <firewall>\n`;
      xml += `                      <rules>\n`;
      xml += `                        <rule id="FW-${i}-${Math.floor(Math.random() * 100)}" action="${this.getRandomChoice(['ALLOW', 'DENY', 'LOG'])}">\n`;
      xml += `                          <source>\n`;
      xml += `                            <ip>${this.generateRandomIP()}</ip>\n`;
      xml += `                            <ports>\n`;
      xml += `                              <port protocol="tcp">${Math.floor(Math.random() * 65535) + 1}</port>\n`;
      xml += `                              <port protocol="udp">${Math.floor(Math.random() * 65535) + 1}</port>\n`;
      xml += `                            </ports>\n`;
      xml += `                          </source>\n`;
      xml += `                          <destination>\n`;
      xml += `                            <ip>${this.generateRandomIP()}</ip>\n`;
      xml += `                            <services>\n`;
      xml += `                              <service name="${this.getRandomChoice(['HTTP', 'HTTPS', 'SSH', 'FTP', 'SMTP'])}" port="${Math.floor(Math.random() * 65535) + 1}" />\n`;
      xml += `                            </services>\n`;
      xml += `                          </destination>\n`;
      xml += `                        </rule>\n`;
      xml += `                      </rules>\n`;
      xml += `                    </firewall>\n`;
      xml += `                  </security>\n`;
      xml += `                </subnet>\n`;
      xml += `              </subnets>\n`;
      xml += `            </network>\n`;
      xml += `          </networks>\n`;
      xml += `        </infrastructure>\n`;
      xml += `      </technology>\n`;

      // Compliance branch
      xml += `      <compliance>\n`;
      xml += `        <frameworks>\n`;
      xml += `          <framework name="${this.getRandomChoice(['SOC2', 'ISO27001', 'NIST', 'FEDRAMP'])}" version="2.0">\n`;
      xml += `            <controls>\n`;
      xml += `              <control id="CTRL-${i}-${Math.floor(Math.random() * 50)}" status="${this.getRandomChoice(['COMPLIANT', 'NON_COMPLIANT', 'PARTIAL'])}">\n`;
      xml += `                <evidence>\n`;
      xml += `                  <documents>\n`;
      xml += `                    <document type="policy" classification="${this.getRandomChoice(['PUBLIC', 'INTERNAL', 'CONFIDENTIAL'])}">\n`;
      xml += `                      <metadata>\n`;
      xml += `                        <created>${new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString()}</created>\n`;
      xml += `                        <version>${Math.floor(Math.random() * 10) + 1}.${Math.floor(Math.random() * 10)}</version>\n`;
      xml += `                        <approvals>\n`;
      xml += `                          <approval role="manager" date="${new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]}" />\n`;
      xml += `                          <approval role="legal" date="${new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]}" />\n`;
      xml += `                        </approvals>\n`;
      xml += `                      </metadata>\n`;
      xml += `                    </document>\n`;
      xml += `                  </documents>\n`;
      xml += `                </evidence>\n`;
      xml += `              </control>\n`;
      xml += `            </controls>\n`;
      xml += `          </framework>\n`;
      xml += `        </frameworks>\n`;
      xml += `      </compliance>\n`;

      xml += `    </department>\n`;
      xml += `  </departments>\n`;
    }

    xml += `</organization>\n`;
    return xml;
  }

  generate(config: XMLGeneratorConfig): void {
    let xmlContent: string;

    switch (config.format) {
      case 'burp':
        xmlContent = this.generateBurpXML(config);
        break;
      case 'nessus':
        xmlContent = this.generateNessusXML(config);
        break;
      case 'project':
        xmlContent = this.generateProjectXML(config);
        break;
      case 'deep-nested':
        xmlContent = this.generateDeepNestedXML(config);
        break;
      case 'generic':
      default:
        xmlContent = this.generateGenericXML(config);
        break;
    }

    const filePath = join(process.cwd(), 'generated', config.filename);
    writeFileSync(filePath, xmlContent, 'utf8');

    console.info(`XML file generated: ${filePath}`);
    console.info(`Format: ${config.format}`);
    console.info(`Records: ${config.totalRecords}`);
    console.info(`File size: ${Math.round(xmlContent.length / 1024)} KB`);
  }
}

function createBurpConfig(): XMLGeneratorConfig {
  return {
    filename: 'test-burp-scan.xml',
    totalRecords: 50,
    format: 'burp',
  };
}

function createLargeBurpConfig(): XMLGeneratorConfig {
  return {
    filename: 'large-burp-scan.xml',
    totalRecords: 18000, // ~13.7MB
    format: 'burp',
  };
}

function createNessusConfig(): XMLGeneratorConfig {
  return {
    filename: 'test-nessus-scan.xml',
    totalRecords: 100,
    format: 'nessus',
  };
}

function createLargeNessusConfig(): XMLGeneratorConfig {
  return {
    filename: 'large-nessus-scan.xml',
    totalRecords: 26200, // ~13.6MB
    format: 'nessus',
  };
}

function createGenericConfig(): XMLGeneratorConfig {
  return {
    filename: 'test-generic-data.xml',
    totalRecords: 25,
    format: 'generic',
    options: {
      rootElement: 'testData',
      includeAttributes: true,
      includeCDATA: true,
    },
  };
}

function createLargeGenericConfig(): XMLGeneratorConfig {
  return {
    filename: 'large-generic-data.xml',
    totalRecords: 41300, // ~13.6MB
    format: 'generic',
    options: {
      rootElement: 'largeTestData',
      includeAttributes: true,
      includeCDATA: true,
    },
  };
}

function createProjectConfig(): XMLGeneratorConfig {
  return {
    filename: 'test-project-controls.xml',
    totalRecords: 20,
    format: 'project',
  };
}

function createDeepNestedConfig(): XMLGeneratorConfig {
  return {
    filename: 'test-deep-nested.xml',
    totalRecords: 10,
    format: 'deep-nested',
  };
}

function createLargeDeepNestedConfig(): XMLGeneratorConfig {
  return {
    filename: 'large-deep-nested.xml',
    totalRecords: 3250, // ~13MB with deep nesting (4KB per record)
    format: 'deep-nested',
  };
}

function main() {
  const generator = new XMLGenerator();
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.info('XML Test Data Generator');
    console.info('');
    console.info('Generates various XML test files for security assessments and testing');
    console.info('');
    console.info('Usage:');
    console.info('  npx tsx app/xml-generator.ts [format]');
    console.info('');
    console.info('Available formats:');
    console.info('  burp        - Burp Suite security scan format (50 issues)');
    console.info('  nessus      - Nessus vulnerability scan format (100 items)');
    console.info('  generic     - Generic XML with nested elements (25 records)');
    console.info('  project     - Security project controls format (20 controls)');
    console.info('  deep-nested - Complex hierarchical structure (10 departments)');
    console.info('  all         - Generate all formats');
    console.info('');
    console.info('Large formats (~13MB each):');
    console.info('  burp-large        - Large Burp Suite scan (18,000 issues)');
    console.info('  nessus-large      - Large Nessus scan (26,200 items)');
    console.info('  generic-large     - Large generic XML (41,300 records)');
    console.info('  deep-nested-large - Large deep hierarchy (3,250 departments)');
    console.info('');
    console.info('Examples:');
    console.info('  npx tsx app/xml-generator.ts burp');
    console.info('  npx tsx app/xml-generator.ts all');
    console.info('');

    // Generate all by default
    generator.generate(createBurpConfig());
    generator.generate(createNessusConfig());
    generator.generate(createGenericConfig());
    generator.generate(createProjectConfig());
    generator.generate(createDeepNestedConfig());
    return;
  }

  const format = args[0].toLowerCase();

  switch (format) {
    case 'burp':
      generator.generate(createBurpConfig());
      break;
    case 'nessus':
      generator.generate(createNessusConfig());
      break;
    case 'generic':
      generator.generate(createGenericConfig());
      break;
    case 'project':
      generator.generate(createProjectConfig());
      break;
    case 'burp-large':
      generator.generate(createLargeBurpConfig());
      break;
    case 'nessus-large':
      generator.generate(createLargeNessusConfig());
      break;
    case 'generic-large':
      generator.generate(createLargeGenericConfig());
      break;
    case 'deep-nested':
      generator.generate(createDeepNestedConfig());
      break;
    case 'deep-nested-large':
      generator.generate(createLargeDeepNestedConfig());
      break;
    case 'all':
      generator.generate(createBurpConfig());
      generator.generate(createNessusConfig());
      generator.generate(createGenericConfig());
      generator.generate(createProjectConfig());
      generator.generate(createDeepNestedConfig());
      break;
    default:
      console.error(`Unknown format: ${format}`);
      console.info(
        'Available formats: burp, nessus, generic, project, deep-nested, burp-large, nessus-large, generic-large, deep-nested-large, all'
      );
      process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { XMLGenerator, type XMLGeneratorConfig };
