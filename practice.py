
import matplotlib.pyplot as plt
import numpy as np

x = [0,5,9,10,15]

y = [0,1,2,3,4]

plt.figure(0)                # the first figure
plt.title('title')

plt.plot(x,y)
plt.xticks(np.arange(min(x), max(x)+1, 1.0))

plt.show()