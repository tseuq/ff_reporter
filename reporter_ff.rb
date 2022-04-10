#!/usr//bin/env ruby
#
# @author : Christian Nicita <quest@freaknet.org>
# @license: This script is released under GPL-3.0 licence
# @whatDo : This script reads basic vulnerability info from Fortify FPR file and produce an xls file with those info.
#           It is a very basic implementation could be improved but it works and gives an help to understand the
#           .fpr file dissected for this porpoise.
#           Run the script to know how to use
#
# @ToDo : 1. implement fpr version control check; 2. xls_extended_report method with all additional parameters;
#         3. implement better errors handling; 4. whatever you could think be useful to report infos from a .fpr file
#

# requirements
require 'axlsx'
require 'nokogiri'
require 'optparse'
require 'zip'

# define a Vulnerability structure for basic infos and methods to get this infos back as array to use to create an xls row
class Vulnerability
  attr_reader :severity, :kingdom, :type, :subtype, :sourcefile

  def initialize(severity:, kingdom:, type:, subtype: "", sourcefile:)
    @severity = severity
    @kingdom = kingdom
    @type = type
    @subtype = subtype
    @sourcefile = sourcefile
  end

  def get
    [@severity, @kingdom, @type, @subtype, @sourcefile]
  end
end

# exted Vulnerability structure with specific Fortify attributes
class VulnerabilityFF < Vulnerability
  attr_reader  :suppressed, :classid, :instanceseverity, :confidence, :probability, :impact, :rule

  def initialize(severity:, kingdom:, type:, subtype: "", sourcefile:, suppressed: 0, classid: "",
                 instanceseverity: "", confidence: "", probability: "", impact: "")
    @severity = severity
    @kingdom = kingdom
    @type = type
    @subtype = subtype
    @sourcefile = sourcefile
    @suppressed = suppressed
    @classid = classid
    @instanceseverity = instanceseverity
    @confidence = confidence
    @probability = probability
    @impact = impact
  end

  def get_extended
    [@severity, @kingdom, @type, @subtype, @sourcefile, @suppressed, @classid, @instanceseverity, @confidence,
     @probability, @impact]
  end
end

# fpr file is a zip file, this class open the fpr file from the constructuor filename if exist and then provide
#   list to list the fpr file content
#   get to provide a single entryname content as row data stream
class FPRExtractor

  # Open the fpr file if exist or exit with error -- exit in class method is not elegant may be should handle
  #       raising the error to the caller. Should implement this in all the code
  def initialize(filename)
    begin
      @fpr = Zip::File.open(filename)
    rescue  => e
      puts 'Error opening file %s [%s] ' %[filename, e]
      exit 1
    end
  end

  # return the list of entries into the fpr file
  def list
    list = Array.new
    @fpr.each do |entry|
      list << entry
    end
    list
  end

  # extract the entry file content named by entryname from fpr file
  def get(entryname)
    begin
      entry = @fpr.get_entry(entryname)
    rescue Errno::ENOENT => e
      puts 'Error extracting %s [%s]' %[entryname, e]
      exit 2
    else
      content = entry.get_input_stream.read
    end
    content
  end
end

class ReporterFF
  def initialize(filename)
    @filename = filename
    fpr = FPRExtractor.new(filename)
    @audit_fvdl = Nokogiri::XML( fpr.get('audit.fvdl') )
    @audit_xml  = Nokogiri::XML( fpr.get('audit.xml') )
    get_vulnerabilities
  end

  def xls_report
    resultsxls = Axlsx::Package.new
    resultswb = resultsxls.workbook


    resultswb.add_worksheet(name: 'Vulnerabilities summary') do |sheet|

      title = sheet.styles.add_style(:bg_color => 'FFFFFFFF', :fg_color => '#00000000', :b => true,
                                     :sz => 14, :border => Axlsx::STYLE_THIN_BORDER,
                                     :alignment => {:horizontal => :center})

      sheet.add_row %w[Severity Kingdom Type Subtype  FileName], :style => title
      @vulnerabilities.each do |vuln|
        sheet.add_row(vuln.get)
      end
    end

    # output file name has the same name of input filename but with different extention
    basename = File.basename(@filename, '.*')
    dirname = File.dirname(@filename)
    outputfile = dirname+'/'+basename+'.xlsx'

    begin
      resultsxls.serialize outputfile
    rescue => e
      puts 'Error occurred writing xlsx file: %s [%s] ' %[outputfile, e]
    end
  end

  private
  def get_vulnerabilities
    @vulnerabilities = Array.new

    @audit_fvdl.remove_namespaces!
    @audit_xml.remove_namespaces!

    vulns = @audit_fvdl.xpath('//Vulnerability')
    rulesinfo = @audit_fvdl.xpath('//EngineData/RuleInfo')
    issues = @audit_xml.xpath('//IssueList')

    vulns.each do |vuln|

      if vuln.at('InstanceID').nil?
        # if there is not InstanceID something went wrong so move to the next
        # it should not be possibile to find a vulnerability with no IstanceID, but let's check in case of malformed file
        next
      else
        instanceid =  vuln.at('InstanceID').text
        istance_audit = issues.search("//Issue[@instanceId='#{instanceid}']")
        if vuln.at('ClassID').nil?
          # it should not be possible so skip
          next
        else
          classid = vuln.at('ClassID').text
        end

        if  vuln.at('Kingdom').nil?
          kingdom = 'no_Kingdom'
        else
          kingdom = vuln.at('Kingdom').text
        end
        if vuln.at('Type').nil?
          type = 'no_Type'
        else
          type = vuln.at('Type').text
        end
        if vuln.at('Subtype').nil?
          subtype = 'no_Subtype'
        else
          subtype = vuln.at('Subtype').text
        end
        if vuln.at('InstanceSeverity').nil?
          instanceseverity = 'no_IstanceSeverity'
        else
          instanceseverity = vuln.at('InstanceSeverity').text
        end
        if vuln.at('Confidence').nil?
          confidence = 'no_Confidence'
        else
          confidence = vuln.at('Confidence').text
        end
        if  vuln.at('SourceLocation').nil?
          sourcefile = 'no_SourceLocation'
        else
          sourcelocation = vuln.at('SourceLocation')
          sourcefile = '%s:%s' % [sourcelocation.attr('path'), sourcelocation.attr('line')]
        end

          # check for suppressed issues
          if istance_audit.attr('suppressed').to_s == 'true'
            suppressed = 1
          else
            suppressed = 0
          end

        rule = rulesinfo.at("Rule[@id='#{classid}']/MetaInfo")
        probability = rule.at("Group[@name ='Probability']").text
        impact = rule.at("Group[@name='Impact']").text

          # check for severity: 1st check for severity setted by auditor into custom template identify by @tag_template
          clevel = istance_audit.at("Tag[@id='#{@tag_template}']")
          # if not custom values has been assigned is needed to check into default assignation
          if clevel.nil?
            if impact.to_f >= 2.5 and probability.to_f >= 2.5
              severity = 'Critical'
            elsif impact.to_f >= 2.5 and probability.to_f <= 2.5
              severity = 'High'
            elsif impact.to_f <= 2.5 and probability.to_f >= 2.5
              severity = 'Medium'
            else
              severity = 'Low'
            end
          else
            severity = clevel.at('Value').text

          end
      end
      @vulnerabilities << VulnerabilityFF.new( severity: severity, kingdom: kingdom, type: type, subtype: subtype,
                                            sourcefile: sourcefile, suppressed: suppressed, classid: classid,
                                               instanceseverity: instanceseverity, confidence: confidence,
                                               probability: probability, impact: impact )
    end
  end

end


# main text
options = {}
option_parser = OptionParser.new do |opts|
  opts.banner = 'Usage: ruby ReporterFF.rb [options]'

  opts.on('-f', '--filename NAME', 'Report file name') { |v| options[:file_name] = v }
  opts.on_tail('-h', '--help',              'This help') { puts opts; exit  }
end

begin
  option_parser.parse!
  if options.empty?
    raise OptionParser::MissingArgument.new('An argument must be selected')
  end
rescue  => e
  puts 'Warning:  %s' %[e]
  puts option_parser
  exit 23
end

fpr = ReporterFF.new(options[:file_name])
fpr.xls_report
