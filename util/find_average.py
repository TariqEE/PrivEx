import pprint
bad_sites = []
if __name__ == '__main__':
  results = {}
  epochs = 0
  with open('bad_share_sites.txt', 'r') as g:
    for line in g:
      bad_sites.append(line.strip())

  with open('consol-results.txt','r') as f:
    for line in f:
      epoch, site, visits = line.strip().split(":")
      if site not in bad_sites:
        if site == 'Other':
          epochs = epochs + 1
        if site in results:
          results[site] = float(visits) + results[site]
        else:
          results[site] = float(visits)

  for key in results:
    results[key] = results[key]/epochs
  print 'Epochs: ', epochs
  for site in sorted(results, key=results.get, reverse=False):
    print site, results[site]
