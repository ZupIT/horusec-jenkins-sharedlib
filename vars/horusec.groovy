def validateConfig(templateString, config) {
  if (config && !config.allWhitespace) {
    return "${templateString}\"${config}\""
  } else {
    return ""
  }
}

def call(body) {
  def config = [:]
  body.resolveStrategy = Closure.DELEGATE_FIRST
  body.delegate = config
  body()


  timeout(time: 30, unit: "MINUTES") {
    stage('Security - Horusec') {
      checkout scm // this will actually download the code to be analyzed

      def HORUSEC_PATH = ".horusec" // default to a hidden folder in $pwd


      // Get the latest version from Amazon S3
      def LATEST_VERSION = sh(
        script: "curl -s https://horusec-cli.s3.amazonaws.com/version-cli-latest.txt",
        returnStdout: true
        ).trim()

      sh("mkdir -p $HORUSEC_PATH/bin")

      sh("curl \"https://horusec-cli.s3.amazonaws.com/$LATEST_VERSION/linux_x64/horusec\" -o \"$HORUSEC_PATH/bin/horusec\"")

      sh("chmod +x $HORUSEC_PATH/bin/horusec")

      // Horusec Server configs
      def HORUSEC_URL = validateConfig("-u=", config.horusecURL)
      def HORUSEC_AUTH = validateConfig("-a=", config.horusecAuth)
      def HORUSEC_REPO = validateConfig("-n=", config.horusecRepository)

      // Horusec general configs
      def HORUSEC_FAIL = validateConfig("-e=", config.shouldFailSilently)
      def HORUSEC_ANALYSIS_TIMEOUT = validateConfig("-t=", config.analysisTimeout)
      def HORUSEC_FILE_FILTER = validateConfig("-f=", config.horusecPathsToInclude)
      def HORUSEC_IGNORE_FILTER = validateConfig("-i=", config.horusecIgnoreFilter)
      def HORUSEC_DISABLE_SSL_CHECK = validateConfig("-S=", config.disableSSLCheck)
      def HORUSEC_IGNORE_SEVERITY = validateConfig("-s=", config.horusecIgnoreSeverity)

      // hashes configs
      def HORUSEC_FP_HASHES = validateConfig("-F=", config.falsePositiveHashes)
      def HORUSEC_ACCEPTED_HASHES = validateConfig("-R=", config.acceptedRiskHashes)

      // output format
      def HORUSEC_OUTPUT_FORMAT = validateConfig("-o=", config.horusecOutputFormat)
      def HORUSEC_JSON_OUTPUT_FILE = validateConfig("-O=", config.horusecJSONOutputFile)

      // timeouts
      def HORUSEC_REQUEST_TIMEOUT = validateConfig("-r=", config.horusecRequestTimeout)
      def HORUSEC_MONITOR_RETRY = validateConfig("-m=", config.horusecMonitorRetryCount)

      // Git and underlying tools configs
      def HORUSEC_COMMIT_AUTHORS = validateConfig("-G=", config.enableCommitAuthors)
      def HORUSEC_COMMIT_HISTORY = validateConfig("--enable-git-history=", config.enableCommitHistory)


      sh("$HORUSEC_PATH/bin/horusec start -p=\"${config.projectPath}\" ${HORUSEC_AUTH} ${HORUSEC_URL} ${HORUSEC_REPO} ${HORUSEC_ANALYSIS_TIMEOUT} ${HORUSEC_FAIL} ${HORUSEC_COMMIT_AUTHORS} ${HORUSEC_COMMIT_HISTORY} ${HORUSEC_FP_HASHES} ${HORUSEC_FILE_FILTER} ${HORUSEC_IGNORE_FILTER} ${HORUSEC_IGNORE_SEVERITY} ${HORUSEC_DISABLE_SSL_CHECK} ${HORUSEC_MONITOR_RETRY} ${HORUSEC_OUTPUT_FORMAT} ${HORUSEC_ACCEPTED_HASHES} ${HORUSEC_REQUEST_TIMEOUT} ${HORUSEC_JSON_OUTPUT_FILE}")
    }
  }
}
