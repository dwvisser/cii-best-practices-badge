# Determine if project sites support HTTPS

# frozen_string_literal: true

class HardenedSitesDetective < Detective
  CHECK =
    [
      'content-security-policy', 'x-content-type-options',
      'x-frame-options', 'x-xss-protection'
    ].freeze
  MET =
    {
      value: 'Met', confidence: 3,
      explanation: 'Found all required security hardening headers (values not'\
        'checked).'
    }.freeze
  UNMET =
    {
      value: 'Unmet', confidence: 5,
      explanation: 'At least one of the required security hardening headers is'\
        'missing.'
    }.freeze
  INPUTS = %i(repo_url homepage_url).freeze
  OUTPUTS = [:hardened_site_status].freeze

  def security_fields_present?(headers)
    CHECK.reduce(true) { |a, e| a & headers.key?(e) }
  end

  def get_headers(evidence, url)
    response = evidence.get(url)
    response.nil? ? {} : response[:metas]
  end

  def check_urls(evidence, homepage_url, repo_url)
    @results = {}
    if !homepage_url.blank? && !repo_url.blank?
      homepage_headers = get_headers(evidence, homepage_url)
      repo_headers = get_headers(evidence, repo_url)
      hardened = security_fields_present?(homepage_headers) &&
                 security_fields_present?(repo_headers)
      @results[:hardened_site_status] = hardened ? MET : UNMET
    end
    @results
  end

  def analyze(evidence, current)
    check_urls(evidence, current[:homepage_url], current[:repo_url])
  end
end
