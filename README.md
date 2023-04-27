# cnc-sarif-formatter
This action will use Coverity API to collect the given project/stream findings and generate a Sarif -format report.

## Prerequisities
This action is run after the CNC or Coverity Analysis run is done, so that there are results are available via Coverity API.

## Available Options
| Option name | Description | Default value | Required |
|-------------|-------------|---------------|----------|
| log_level | Logging level | DEBUG | false |
| url | Cloud Native Coverity (CNC) or Coverity on-premm URL | - | true |
| project | Coverity project name. | - | false |
| stream | Coverity stream name. | ${{github.ref_name}} | false |
| password | User password for Coverity | - | true |
| username | Username for Coverity | - | true |
| impactNameList | Comma separated list of impact names for filttering. Options: high, medium, low | high,medium,low | false |
| statusNamesList | Comma separated list of statuses for filttering. Options: New,Triaged,Dismissed,Fixed | New,Triaged,Dismissed,Fixed | false |
| outputFile | Filename with path where it will be created, example: github.workspace/cncFindings.sarif.json | ${{github.workspace}}/cncFindings.sarif.json | false |


## Usage examples
```yaml
    - name: CNC Analysis with synopsys-action
      uses: synopsys-sig/synopsys-action@v1.2.0
      with:
        coverity_url: ${{ secrets.cnc_url }}
        coverity_user: ${{ secrets.cnc_username }}
        coverity_passphrase: ${{ secrets.cnc_passphare }}
        coverity_project_name: ${{github.repository}}
        coverity_stream_name: ${{github.ref_name}}
    - uses: lejouni/cnc-sarif-formatter@main
      with:
        url:  ${{ secrets.cnc_url }}
        username: ${{ secrets.cnc_username }}
        password: ${{ secrets.cnc_passphare }}
        stream: ${{github.ref_name}}
        outputFile: ${{github.workspace}}/cnc-scan-results.sarif.json

    - name: Upload SARIF file
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: ${{github.workspace}}/cnc-scan-results.sarif.json
      continue-on-error: true
```