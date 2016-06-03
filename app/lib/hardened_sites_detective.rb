# Determine if project sites support HTTPS

# frozen_string_literal: true

class HardenedSitesDetective < Detective
  XCTO = 'x-content-type-options'
  NOSNIFF = 'nosniff'
  CHECK =
    [
      'content-security-policy', XCTO, 'x-frame-options', 'x-xss-protection'
    ].freeze
  MET =
    {
      value: 'Met', confidence: 3,
      explanation: 'Found all required security hardening headers.'
    }.freeze
  UNMET_MISSING =
    {
      value: 'Unmet', confidence: 5,
      explanation: 'One or more of the required security hardening headers '\
        'is missing.'
    }.freeze
  UNMET_NOSNIFF =
    {
      value: 'Unmet', confidence: 5,
      explanation: 'X-Content-Type-Options was not set to "nosniff".'
    }.freeze

  INPUTS = %i(repo_url homepage_url).freeze
  OUTPUTS = [:hardened_site_status].freeze

  def security_fields_present?(headers_list)
    result = true
    headers_list.each do |headers|
      result &&= CHECK.reduce(true) { |a, e| a & headers.key?(e) }
    end
    result
  end

  def get_headers(evidence, url)
    response = evidence.get(url)
    response.nil? ? {} : response[:meta]
  end

  def check_nosniff?(headers_list)
    result = true
    headers_list.each do |response_headers|
      xcto = response_headers[XCTO]
      result &&= xcto.nil? ? false : xcto.casecmp(NOSNIFF).zero?
    end
    result
  end

  def check_urls(evidence, homepage_url, repo_url)
    @results = {}
    if !homepage_url.blank? && !repo_url.blank?
      homepage_headers = get_headers(evidence, homepage_url)
      repo_headers = get_headers(evidence, repo_url)
      hardened = security_fields_present?([homepage_headers, repo_headers])
      @results[:hardened_site_status] = hardened ? MET : UNMET_MISSING
      hardened ||= check_nosniff?([homepage_headers, repo_headers])
      @results[:hardened_site_status] = UNMET_NOSNIFF unless hardened
    end
    @results
  end

  def analyze(evidence, current)
    check_urls(evidence, current[:homepage_url], current[:repo_url])
  end
end
