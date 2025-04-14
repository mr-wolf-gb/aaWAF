## **2025-04-14 V5.6 **
[Remove] Remove SQL injection regular matching rules
[Optimization] SQL injection detection fully adopts semantic analysis detection method, with accuracy increased to 99.10% and false positives reduced to 0.89%
PS: Upgrades will not automatically remove regular matching rules
<br/>

## **2025-04-08 V5.5 **

【 Open Source 】 The code has been opened source https://github.com/aaPanel/aaWAF
[Fix] Fix bug in automatic renewal
[Fix] Fix bugs in IP groups
[Fix] Fixed a bug in port forwarding that affects Nginx stability
<br/>


## **2025-03-18 V5.4 **
【 Add 】 3D map added to homepage<br/>
[Fix] Fix the issue of adding failed due to multiple SSL ports<br/>


## **2025-02-24 V5.3 **
[Add] Batch renewal of SSl certificates<br/>
[Add] Add SSL certificate automatic renewal upon expiration (certificates less than 20 days will be automatically triggered)<br/>
[Add] Homepage adds spider crawling details<br/>
[Fix] Fix SQL injection engine false positive<br/>
Subsequent update plan:
1. Fix the issue where forced HTTPS cannot be automatically enabled due to renewal
2. Increase LRU cache to accelerate research and judgment speed
3. Add URL statistics list display
4. Add attack alarm function, renewal alarm, etc
Coming soon
<br/>
<br/>



## **2025-01-02 V5.2 **
[Add] Increase the current limiting function of the waiting room<br/>
[Add] Add traffic restriction function<br/>
[Optimization] Reduce CPU usage by an average of 2%<br/>
[Fix] Fix errors caused by nil judgment<br/>
<br/>
<br/>


## **2024-12-19 V5.1 **
[Add] Add Shenma Spider IP Library<br/>
[Optimization] Optimize the basic CC logic to reduce false positive interception by 5% -10%<br/>
[Optimization] Change spider IP to IP address range<br/>
[Fix] Issue where custom CC function blocks and cannot be unblocked<br/>
[Fix] Error caused by SQL injection engine<br/>
[Fix] Known BUG<br/>
The next version will add crawler defense - dynamic encryption function, traffic restriction function, and look forward to it to the fullest
<br/>
<br/>