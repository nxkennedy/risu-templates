# Copyright (c) 2010-2017 Jacob Hammack.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

#So we can convert some ip addresses into ranges

module Risu
	module Templates
		class SatFailedStigCheck < Risu::Base::TemplateBase
			include TemplateHelper

			def initialize
				@template_info =
				{
					:name => "custom_failed_stig_check",
					:author => "nxkennedy",
					:version => "0.0.1",
					:renderer => "PDF",
					:description => "Generates a failed STIG check report"
				}
			end

			### so we can calc ip ranges
			def to_ranges(ips)
			  ips = ips.map {|ip| IPAddr.new(ip).to_i }.uniq.sort

			  prev = ips[0]
			  ips
			    .slice_before {|e|
			      prev2, prev = prev, e
			      prev2 + 1 != e
			    }
			    .map {|addrs| if addrs.length > 1 then [addrs[0], addrs[-1]] else addrs end }
			    .map {|addrs| addrs.map{|ip| IPAddr.new(ip, Socket::AF_INET)}.join(" - ") }
			end

			@@table_number = 1 # keep track of tables we create with a class var
			def print_audit_findings(failed_audit_checks, text, color, cat_count, last=false)

				# evaluate and start loop
				if failed_audit_checks.length > 0
					plugins = []
					seen_vuln_ids = []
					number = 1
					puts "\n[+] #{text}:"
					puts "-----"
					puts "- Raw Count: #{failed_audit_checks.length}"
					puts "- Unique: #{cat_count.to_s}"

					# CAT Finding X title
					title text + " (#{cat_count.to_s})", 18, color

					# risk rating
					risk = ""
					case text
					when "CAT I Findings"
						risk = "High"
					when "CAT II Findings"
						risk = "Medium"
					when "CAT III Findings"
						risk = "Low"
					end

					# first iteration to snag plugin names
					failed_audit_checks.each do |fc|
						# done to separate windows server and win 7 compliance checks as both are called "Windows Compliance Checks"
						check = [fc.plugin_name, fc.cm_compliance_audit_file]
						unless plugins.include?(check)
							plugins << check
						end
					end

					########## MAIN LOOP

					# for each unique plugin name we found
					plugins.each do |plugin|
						# let this wipe clean for each plugin
						plugin_data = {
							:audit_data => [],
							:tech_details => [],
							:hostlist => "",
							:control_nums => [],
							:audit_file => ""
						}

						#failed_checks is model collection (Item.where(:cm_compliance_result => "FAILED")
						failed_audit_checks.each do |fc|
							print "Collecting failed #{plugin[0]} (#{plugin[1]})... \r"
							check = [fc.plugin_name, fc.cm_compliance_audit_file]
							# ensure we're only dealing with one plugin at a time
							if check != plugin
								next
							end


							#@hosts = Item.where(:plugin_id => fc.plugin_id).group(:host_id)

							@hosts = Item.where(:cm_compliance_audit_file => fc.cm_compliance_audit_file).group(:host_id)

							# this is the magic to parse out the cat info
							compliance_refs = Hash[fc.cm_compliance_reference.split(",").map {|el| el.split("|")}]
							# {"800-53"=>"IA-5", "CSF"=>"PR.AC-1", "ITSG-33"=>"IA-5", "800-171"=>"3.5.9", "CAT"=>"II", "CCI"=>"CCI-000366", "Group-ID"=>"V-63985", "Rule-ID"=>"SV-78475r1_rule", "STIG-ID"=>"VCWN-06-000024\n"}

							# Build a hash of all the info we want from the object
							# most of these keys are not being used but you should keep this mapping for later templates
							audit_data = {
								"plugin_name" => fc.plugin_name,
								"description" => fc.cm_compliance_info,
								"check_name" => fc.cm_compliance_check_name.split(" - ")[1],
								"nist_ref" => compliance_refs["800-53"],
								"vuln_id" => compliance_refs["Group-ID"],
								"cat_score" => compliance_refs["CAT"],
								"solution" => fc.cm_compliance_solution,
								"see_also" => fc.cm_compliance_see_also,
								"audit_file" => fc.cm_compliance_audit_file,
								"tech_details" => fc.cm_compliance_actual_value,
								}


							# bounces between Group-ID and Vuln-ID cuz stigs don't care about naming consistency :(
							if audit_data["vuln_id"] == nil
								audit_data["vuln_id"] = compliance_refs["Vuln-ID"]
							end

							# now let's deterimine if we've seen it before
							if seen_vuln_ids.include?(audit_data["vuln_id"])
								next # we've seen this vuln already, let's keep moving
							else
								seen_vuln_ids << audit_data["vuln_id"]
								plugin_data[:audit_file] << audit_data["audit_file"]
							end

							# store our control numbers for organization in the report
							unless audit_data["nist_ref"] == nil || plugin_data[:control_nums].include?(audit_data["nist_ref"])
								plugin_data[:control_nums] << audit_data["nist_ref"]
							end


							# Our data has passed the test. Now append our table data to our plugins hash
							plugin_data[:tech_details] << ["", audit_data["vuln_id"], audit_data["check_name"], audit_data["tech_details"]]
							# comment out the line above and uncomment the one below if you need additional details for findings
							# plugin_data[:tech_details] << ["", audit_data["vuln_id"], fc.cm_compliance_info, fc.cm_compliance_solution]
							####################

							hosts_to_scans = Hash.new []
							@hosts.each do |host|
								ho = Host.find_by_id(host.host_id)
								scan = Report.find_by_id(ho.report_id).name

								if hosts_to_scans.has_key?(scan)
									hosts_to_scans[scan] += [ho.ip]
								else
									hosts_to_scans[scan] = []
									hosts_to_scans[scan] += [ho.ip]
								end
							end

							hosts_to_scans.each do |scan, ips|
								# call our "to_ranges" function against our host list
								unless plugin_data[:hostlist].include?(scan)
									plugin_data[:hostlist] << "#{scan}: (#{to_ranges(hosts_to_scans[scan]).join(', ')})\n"
								end
							end

						end # fc for end

						output.font_size(16) do
							text "#{plugin[0]}\n(#{plugin[1]})"
						end
						text "Hosts (#{@hosts.length})", :style => :bold
						text "\n"

						release = plugin_data[:audit_file].split("DISA_STIG_")[1].split(".audit")[0].split("_")[-1].downcase().split("r")[1]

						stock_description = "The baseline configuration of the #{plugin[0].split("Compliance")[0].strip()} installations are not fully
						hardened and secured based on the DISA STIG baseline standard. The
						installations are deployed with configurations that are lacking in
						[DESCRIBE FINDINGS, ex. audit protection, backup configuration, etc]."

						stock_recommendation = "Configure the #{plugin[0].split("Compliance")[0].strip()} installations in accordance
						with the #{plugin_data[:audit_file].split("DISA_STIG_")[1].split(".audit")[0].split("_")[0..-2].join(" ")} Security Technical Implementation Guide: Release: #{release}, Benchmark Date: [dd mm yyyy]."

						stock_tech_details = "This was found during an automated STIG audit review using the #{plugin_data[:audit_file].split("DISA_STIG_")[1].split(".audit")[0].split("_")[0..-2].join(" ")}
						Security Technical Implementation Guide: Release: #{release}.\n
						The Table below shows the STIG CAT level, Vuln ID, Rule Title, and SAT Comments for the open finding(s).\n\n"

						stock_impact = "#{risk}: Not fully establishing and configuring systems according to a secure baseline
						standard can place the platform, data, and connected systems at risk. Impact is rated at a #{risk} level based on #{text.split("Findings")[0].strip()} STIG categorizations."

						stock_exploitability = "#{risk}: Attackers may take advantage of a variety of configuration shortcomings when
						a system is not configured to a secure baseline. Attacks against #{plugin[0].split("Compliance")[0].strip()} installations
						could be attempted by an insider threat on the local network."

						# classifcation marker
						text "#{Report.classification.upcase}"
						print "Writing failed #{plugin[0]} (#{plugin[1]}) to report... \r"
						# table for our findings. It's a loop because of prawn formatting.
						output.table([
								["#{risk}\n\n", "(#{Report.classification.upcase}) #{Report.network.upcase}-#{risk[0]}-0#{number}: #{plugin[0]}"],
								["NIST Security Control Number", "CM-6"],
								["Description", stock_description],
								["Affected Scope", plugin_data[:hostlist]],
								["Impact", stock_impact],
								["Exploitability", stock_exploitability],
								["Recommendations", stock_recommendation],
								["Technical Details", stock_tech_details],
							], :width => 530, :column_widths => { 0 => 100, 1 => 430}) do
							### keep this for actual record of control numbers
							# ["NIST Security Control Number", plugin_data[:control_nums].uniq.join(", ")]
							column(0).style(:background_color => 'f2f3f4' ) # gray
							row(0).style(:font_style => :bold, :background_color => color.split("#")[1])
							cells.borders = [:top, :bottom, :left, :right]
						end
						# cont. of Tech details because having issues putting a table in a table with width formatting;
						# we use this as a header because we want to sort our vuln ids from lowest to highest
						output.table([["", "Vuln ID", "Rule Title", "Comments"]], :width => 530, :column_widths => [100, 75, 155, 200]) do
							column(0).style(:background_color => 'f2f3f4' )
						end
						# our actual tech details
						output.table(plugin_data[:tech_details].sort(), :width => 530, :column_widths => [100, 75, 155, 200]) do
							column(0).style(:background_color => 'f2f3f4' )
						end
						# our table number
						output.table([["(#{Report.classification.upcase}) Table #{@@table_number} - #{plugin[0]} #{text.split("Findings")[0].strip()} Findings"]], :width => 530, :column_widths => [530]) do
							cells.style(:font_style => :bold, :align => :center)
						end
						text "\n\n\n"
						printf("%-10s %10s\n", "Writing failed #{plugin[0]} (#{plugin[1]}) to report...", "[DONE]")
						@output.start_new_page if last == false
						number += 1
						@@table_number += 1
					end # plugins for end
				end #if end
			end


			def render output
				text Report.classification.upcase, :align => :center
				text "\n"

				report_title Report.title
				report_subtitle "Failed STIG Checks"
				report_author "This report was prepared by\n#{Report.author}"
				text "\n\n\n"

				print "\n[-] Analyzing database for failed STIG checks....\r"
				cat_totals = Item.failed_audit_check_count
				printf("%-10s %10s\n", "[-] Analyzing database for failed STIG checks....", "[DONE]")
				puts "----"
				unless cat_totals == 0
					title "Summary"
					output.table([["Category", "Findings", "Unique Findings"]], :column_widths => [100, 100, 100]) do
						row(0).style(:font_style => :bold, :background_color => 'D0D0D0')
					end
					output.table(cat_totals, :column_widths => [100, 100, 100])
					text "\n\n"
					cat1_c = cat_totals[0][2]
					cat2_c = cat_totals[1][2]
					cat3_c = cat_totals[2][2]

					# If you uncomment the med/low change the true in high to false for a new page after it
					print_audit_findings(Item.failed_audit_check_cat1, "CAT I Findings", Risu::GRAPH_COLORS[0], cat1_c)
					print_audit_findings(Item.failed_audit_check_cat2, "CAT II Findings", Risu::GRAPH_COLORS[1], cat2_c, false)
					print_audit_findings(Item.failed_audit_check_cat3, "CAT III Findings", Risu::GRAPH_COLORS[2], cat3_c, true)
					#print_audit_findings(Item.low_risks_unique, "Low Findings", Risu::GRAPH_COLORS[3], true) if Item.low_risks_unique.to_a.size != 0

					output.number_pages "<page> of <total>", :at => [output.bounds.right - 75, 0], :width => 150, :page_filter => :all
				end
			end
		end
	end
end
