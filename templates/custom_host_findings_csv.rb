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


module Risu
	module Templates
		class HostFindingsCSV < Risu::Base::TemplateBase

			#
			#
			def initialize
				@template_info =
				{
					:name => "custom_host_findings_csv",
					:author => "nxkennedy",
					:version => "0.0.1",
					:renderer => "CSV",
					:description => "Generates a vulnerability report by host and outputs to CSV"

				}
			end

			# Writes out a CSV block for the risks passed.
			# @param risks, A query from the Plugin model of the risks
			#
			def csv risks
				risks.order(:cvss_base_score).each do |plugin|
					items = Item.where(:plugin_id => plugin.id).group(:host_id)

					items.each do |item|
						# Skip all PostProcssed Items
						if item.severity == -1
							next
						end

						host = Host.where(:id => item.host_id).first
                        scan = Report.find_by_id(host.report_id).name

                        solution = plugin.solution.gsub("\n", " ").gsub(",", "")
                        details = item.plugin_output.gsub("\n", " ").gsub(",", "")

						@output.text "#{scan}, #{host.ip}, #{host.fqdn}, #{host.netbios}, #{item.plugin_name}, #{details}, #{plugin.risk_factor}, #{plugin.cvss_base_score}, #{solution}"
					end
				end
			end

			# TODO doc
			#
			def render output
				@output.text "Scan, IP Address, FQDN, Netbios Name, Finding, Finding Details, Risk Factor, CVSS Base Score, Solution"
				csv Plugin.critical_risks.order(cvss_base_score: :desc)
				csv Plugin.high_risks.order(cvss_base_score: :desc)
			end
		end
	end
end
